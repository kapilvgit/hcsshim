//go:build linux
// +build linux

package securitypolicy

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"testing/quick"
	"time"

	oci "github.com/opencontainers/runtime-spec/specs-go"
)

func newCommandFromInternal(args []string) CommandArgs {
	command := CommandArgs{}
	command.Length = len(args)
	command.Elements = make(map[string]string)
	for i, arg := range args {
		command.Elements[fmt.Sprint(i)] = arg
	}
	return command
}

func newEnvRulesFromInternal(rules []EnvRuleConfig) EnvRules {
	envRules := EnvRules{}
	envRules.Length = len(rules)
	envRules.Elements = make(map[string]EnvRuleConfig)
	for i, rule := range rules {
		envRules.Elements[fmt.Sprint(i)] = rule
	}
	return envRules
}

func newLayersFromInternal(hashes []string) Layers {
	layers := Layers{}
	layers.Length = len(hashes)
	layers.Elements = make(map[string]string)
	for i, hash := range hashes {
		layers.Elements[fmt.Sprint(i)] = hash
	}
	return layers
}

func newOptionsFromInternal(optionsInternal []string) Options {
	options := Options{}
	options.Length = len(optionsInternal)
	options.Elements = make(map[string]string)
	for i, arg := range optionsInternal {
		options.Elements[fmt.Sprint(i)] = arg
	}
	return options
}

func newMountsFromInternal(mountsInternal []mountInternal) Mounts {
	mounts := Mounts{}
	mounts.Length = len(mountsInternal)
	mounts.Elements = make(map[string]Mount)
	for i, mount := range mountsInternal {
		mounts.Elements[fmt.Sprint(i)] = Mount{
			Source:      mount.Source,
			Destination: mount.Destination,
			Options:     newOptionsFromInternal(mount.Options),
			Type:        mount.Type,
		}
	}

	return mounts
}

func securityPolicyFromInternal(p *generatedContainers) *SecurityPolicy {
	securityPolicy := new(SecurityPolicy)
	securityPolicy.AllowAll = false
	securityPolicy.Containers.Length = len(p.containers)
	securityPolicy.Containers.Elements = make(map[string]Container)
	for i, c := range p.containers {
		container := Container{
			AllowElevated: c.AllowElevated,
			WorkingDir:    c.WorkingDir,
			Command:       newCommandFromInternal(c.Command),
			EnvRules:      newEnvRulesFromInternal(c.EnvRules),
			Layers:        newLayersFromInternal(c.Layers),
			Mounts:        newMountsFromInternal(c.Mounts),
		}
		securityPolicy.Containers.Elements[fmt.Sprint(i)] = container
	}
	return securityPolicy
}

func toOCIMounts(mounts []mountInternal) []oci.Mount {
	result := make([]oci.Mount, len(mounts))
	for i, mount := range mounts {
		result[i] = oci.Mount{
			Source:      mount.Source,
			Destination: mount.Destination,
			Options:     mount.Options,
			Type:        mount.Type,
		}
	}
	return result
}

func Test_MarshalRego(t *testing.T) {
	f := func(p *generatedContainers) bool {
		base64policy, err := securityPolicyFromInternal(p).EncodeToString()

		if err != nil {
			t.Errorf("unable to encode policy to base64: %v", err)
		}

		defaultMounts := toOCIMounts(generateMounts(testRand))
		privilegedMounts := toOCIMounts(generateMounts(testRand))

		_, err = NewRegoPolicyFromBase64Json(base64policy, defaultMounts, privilegedMounts)
		if err != nil {
			t.Errorf("unable to convert policy to rego: %v", err)
		}

		return !t.Failed()
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 4}); err != nil {
		t.Errorf("Test_MarshalRego failed: %v", err)
	}
}

// Verify that RegoSecurityPolicyEnforcer.EnforceDeviceMountPolicy doesn't
// return an error when there's a matching root hash in the policy
func Test_Rego_EnforceDeviceMountPolicy_Matches(t *testing.T) {
	f := func(p *generatedContainers) bool {
		securityPolicy := securityPolicyFromInternal(p)
		policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy, []oci.Mount{}, []oci.Mount{})
		if err != nil {
			t.Errorf("unable to convert policy to rego: %v", err)
		}

		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		target := generateMountTarget(r)
		rootHash := selectRootHashFromContainers(p, r)

		err = policy.EnforceDeviceMountPolicy(target, rootHash)

		// getting an error means something is broken
		return err == nil
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_EnforceDeviceMountPolicy_Matches failed: %v", err)
	}
}

// Verify that RegoSecurityPolicyEnforcer.EnforceDeviceMountPolicy will
// return an error when there's no matching root hash in the policy
func Test_Rego_EnforceDeviceMountPolicy_No_Matches(t *testing.T) {
	f := func(p *generatedContainers) bool {
		securityPolicy := securityPolicyFromInternal(p)
		policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy, []oci.Mount{}, []oci.Mount{})
		if err != nil {
			t.Errorf("unable to convert policy to rego: %v", err)
		}

		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		target := generateMountTarget(r)
		rootHash := generateInvalidRootHash(r)

		err = policy.EnforceDeviceMountPolicy(target, rootHash)

		// we expect an error, not getting one means something is broken
		return err != nil
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_EnforceDeviceMountPolicy_No_Matches failed: %v", err)
	}
}

type regoOverlayTestConfig struct {
	layers      []string
	containerID string
	policy      *RegoPolicy
}

func setupRegoOverlayTest(gc *generatedContainers, valid bool) (tc *regoOverlayTestConfig, err error) {
	securityPolicy := securityPolicyFromInternal(gc)
	policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy, []oci.Mount{}, []oci.Mount{})
	if err != nil {
		return nil, err
	}

	containerID := generateContainerID(testRand)
	c := selectContainerFromContainers(gc, testRand)

	var layerPaths []string
	if valid {
		layerPaths, err = createValidOverlayForContainer(policy, c, testRand)
		if err != nil {
			return nil, fmt.Errorf("error creating valid overlay: %w", err)
		}
	} else {
		layerPaths, err = createInvalidOverlayForContainer(policy, c, testRand)
		if err != nil {
			return nil, fmt.Errorf("error creating invalid overlay: %w", err)
		}
	}

	return &regoOverlayTestConfig{
		layers:      layerPaths,
		containerID: containerID,
		policy:      policy,
	}, nil
}

type regoContainerTestConfig struct {
	envList     []string
	argList     []string
	workingDir  string
	containerID string
	policy      *RegoPolicy
}

func setupRegoContainerTest(gc *generatedContainers) (tc *regoContainerTestConfig, err error) {
	securityPolicy := securityPolicyFromInternal(gc)
	policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy, []oci.Mount{}, []oci.Mount{})
	if err != nil {
		return nil, err
	}

	containerID := generateContainerID(testRand)
	c := selectContainerFromContainers(gc, testRand)

	layerPaths, err := createValidOverlayForContainer(policy, c, testRand)
	if err != nil {
		return nil, fmt.Errorf("error creating valid overlay: %w", err)
	}

	err = policy.EnforceOverlayMountPolicy(containerID, layerPaths)
	if err != nil {
		return nil, fmt.Errorf("error mounting filesystem: %w", err)
	}

	envList := buildEnvironmentVariablesFromContainerRules(c, testRand)

	return &regoContainerTestConfig{
		envList:     envList,
		argList:     c.Command,
		workingDir:  c.WorkingDir,
		containerID: containerID,
		policy:      policy,
	}, nil
}

// Verify that RegoSecurityPolicyEnforcer.EnforceOverlayMountPolicy will
// return an error when there's no matching overlay targets.
func Test_Rego_EnforceOverlayMountPolicy_No_Matches(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupRegoOverlayTest(p, false)
		if err != nil {
			t.Error(err)
			return false
		}

		err = tc.policy.EnforceOverlayMountPolicy(tc.containerID, tc.layers)

		// not getting an error means something is broken
		return err != nil
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_EnforceOverlayMountPolicy_No_Matches failed: %v", err)
	}
}

// Verify that RegoSecurityPolicyEnforcer.EnforceOverlayMountPolicy doesn't
// return an error when there's a valid overlay target.
func Test_Rego_EnforceOverlayMountPolicy_Matches(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupRegoOverlayTest(p, true)
		if err != nil {
			t.Error(err)
			return false
		}

		err = tc.policy.EnforceOverlayMountPolicy(tc.containerID, tc.layers)

		// getting an error means something is broken
		return err == nil
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_EnforceOverlayMountPolicy_Matches: %v", err)
	}
}

func Test_Rego_EnforceDeviceUmountPolicy_Removes_Device_Entries(t *testing.T) {
	f := func(p *generatedContainers) bool {
		securityPolicy := securityPolicyFromInternal(p)
		policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy, []oci.Mount{}, []oci.Mount{})
		if err != nil {
			t.Error(err)
			return false
		}

		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		target := generateMountTarget(r)
		rootHash := selectRootHashFromContainers(p, r)

		err = policy.EnforceDeviceMountPolicy(target, rootHash)
		if err != nil {
			return false
		}

		err = policy.EnforceDeviceUnmountPolicy(target)
		if err != nil {
			return false
		}

		devices := policy.data["devices"].(map[string]string)

		_, found := devices[target]
		return !found
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_EnforceDeviceUmountPolicy_Removes_Device_Entries failed: %v", err)
	}
}

func Test_Rego_EnforceCreateContainer(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupRegoContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, tc.envList, tc.workingDir)

		// getting an error means something is broken
		return err == nil
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_EnforceCreateContainer: %v", err)
	}
}

func Test_Rego_EnforceCommandPolicy_NoMatches(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupRegoContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, generateCommand(testRand), tc.envList, tc.workingDir)

		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid command")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_EnforceCommandPolicy_NoMatches: %v", err)
	}
}

func Test_Rego_EnforceEnvironmentVariablePolicy_NotAllMatches(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupRegoContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		envList := append(tc.envList, generateNeverMatchingEnvironmentVariable(testRand))
		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, envList, tc.workingDir)

		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid env list")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_EnforceEnvironmentVariablePolicy_NotAllMatches: %v", err)
	}
}

func Test_Rego_EnforceEnvironmentVariablePolicy_Re2Match(t *testing.T) {
	p := generateContainers(testRand, 1)

	container := generateContainersContainer(testRand, 1, 1)
	// add a rule to re2 match
	re2MatchRule := EnvRuleConfig{
		Strategy: EnvVarRuleRegex,
		Rule:     "PREFIX_.+=.+",
	}
	container.EnvRules = append(container.EnvRules, re2MatchRule)
	p.containers = append(p.containers, container)

	tc, err := setupRegoContainerTest(p)
	if err != nil {
		t.Error(err)
		return
	}

	envList := append(tc.envList, "PREFIX_FOO=BAR")
	err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, envList, tc.workingDir)

	// getting an error means something is broken
	if err != nil {
		t.Fatalf("expected nil error got: %v", err)
	}
}

func Test_Rego_WorkingDirectoryPolicy_NoMatches(t *testing.T) {
	testFunc := func(gc *generatedContainers) bool {
		tc, err := setupRegoContainerTest(gc)
		if err != nil {
			t.Error(err)
			return false
		}

		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, tc.envList, randString(testRand, 20))
		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid working directory")
	}

	if err := quick.Check(testFunc, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_WorkingDirectoryPolicy_NoMatches: %v", err)
	}
}

type regoMountTestConfig struct {
	sandboxID   string
	containerID string
	container   *securityPolicyContainer
	mountSpec   *oci.Spec
	policy      *RegoPolicy
}

func setupRegoMountTest(gc *generatedContainers) (tc *regoMountTestConfig, err error) {
	fmt.Printf("setting up rego test\n")
	securityPolicy := securityPolicyFromInternal(gc)
	fmt.Printf("default mounts\n")
	defaultMounts := generateMounts(testRand)
	fmt.Printf("privileged mounts\n")
	privilegedMounts := generateMounts(testRand)
	fmt.Printf("done with intial mounts mounts\n")

	policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy,
		toOCIMounts(defaultMounts),
		toOCIMounts(privilegedMounts))
	if err != nil {
		return nil, err
	}

	containerID := generateContainerID(testRand)
	c := selectContainerFromContainers(gc, testRand)

	layerPaths, err := createValidOverlayForContainer(policy, c, testRand)
	if err != nil {
		return nil, fmt.Errorf("error creating valid overlay: %w", err)
	}

	err = policy.EnforceOverlayMountPolicy(containerID, layerPaths)
	if err != nil {
		return nil, fmt.Errorf("error mounting filesystem: %w", err)
	}

	envList := buildEnvironmentVariablesFromContainerRules(c, testRand)

	err = policy.EnforceCreateContainerPolicy(containerID, c.Command, envList, c.WorkingDir)
	if err != nil {
		return nil, fmt.Errorf("error creating container: %w", err)
	}

	sandboxID := generateSandboxID(testRand)
	mountSpec := buildMountSpecFromMountArray(c.Mounts, sandboxID, testRand)
	fmt.Printf("%d is length of mountSpec at 1\n", len(mountSpec.Mounts))
	defaultMountSpec := buildMountSpecFromMountArray(defaultMounts, sandboxID, testRand)
	fmt.Printf("%d is length of defaultMountSpec at 1\n", len(defaultMountSpec.Mounts))

	privilegedMountSpec := buildMountSpecFromMountArray(privilegedMounts, sandboxID, testRand)
	fmt.Printf("%d is length of privilegedMountSpec at 1\n", len(privilegedMountSpec.Mounts))

	mountSpec.Mounts = append(mountSpec.Mounts, defaultMountSpec.Mounts...)
	if c.AllowElevated {
		fmt.Printf("doing privileged\n")
		mountSpec.Mounts = append(mountSpec.Mounts, privilegedMountSpec.Mounts...)
	}

	fmt.Printf("%d is length of mountSpec at 2\n", len(mountSpec.Mounts))

	return &regoMountTestConfig{
		container:   c,
		containerID: containerID,
		sandboxID:   sandboxID,
		mountSpec:   mountSpec,
		policy:      policy,
	}, nil
}

func Test_Rego_EnforceMountPolicy(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupRegoMountTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		err = tc.policy.EnforceMountPolicy(tc.sandboxID, tc.containerID, tc.mountSpec)

		// getting an error means something is broken
		return err == nil
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_EnforceMountPolicy: %v", err)
	}
}

func Test_Rego_ExtendDefaultMounts(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupRegoMountTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		defaultMounts := generateMounts(testRand)
		tc.policy.ExtendDefaultMounts(toOCIMounts(defaultMounts))

		additionalMounts := buildMountSpecFromMountArray(defaultMounts, tc.sandboxID, testRand)
		tc.mountSpec.Mounts = append(tc.mountSpec.Mounts, additionalMounts.Mounts...)

		err = tc.policy.EnforceMountPolicy(tc.sandboxID, tc.containerID, tc.mountSpec)

		return err == nil
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_ExtendDefaultMounts: %v", err)
	}
}

func Test_Rego_EnforceMountPolicy_NoMatches(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupRegoMountTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		invalidMounts := generateMounts(testRand)
		additionalMounts := buildMountSpecFromMountArray(invalidMounts, tc.sandboxID, testRand)
		tc.mountSpec.Mounts = append(tc.mountSpec.Mounts, additionalMounts.Mounts...)

		err = tc.policy.EnforceMountPolicy(tc.sandboxID, tc.containerID, tc.mountSpec)

		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid mount list")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_EnforceMountPolicy_NoMatches: %v", err)
	}
}

func Test_Rego_EnforceMountPolicy_NotAllOptionsFromConstraints(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupRegoMountTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		input_mounts := tc.mountSpec
		mindex := randMinMax(testRand, 0, int32(len(tc.mountSpec.Mounts)-1))
		options := input_mounts.Mounts[mindex].Options
		input_mounts.Mounts[mindex].Options = options[:len(options)-1]

		err = tc.policy.EnforceMountPolicy(tc.sandboxID, tc.containerID, input_mounts)

		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid mount list")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_EnforceMountPolicy_NotAllOptionsFromConstraints: %v", err)
	}
}

func Test_Rego_EnforceMountPolicy_BadSource(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupRegoMountTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		index := randMinMax(testRand, 0, int32(len(tc.mountSpec.Mounts)-1))
		tc.mountSpec.Mounts[index].Source = randString(testRand, maxGeneratedMountSourceLength)

		err = tc.policy.EnforceMountPolicy(tc.sandboxID, tc.containerID, tc.mountSpec)

		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid mount list")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_EnforceMountPolicy_BadSource: %v", err)
	}
}

func Test_Rego_EnforceMountPolicy_BadDestination(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupRegoMountTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		index := randMinMax(testRand, 0, int32(len(tc.mountSpec.Mounts)-1))
		tc.mountSpec.Mounts[index].Destination = randString(testRand, maxGeneratedMountDestinationLength)

		err = tc.policy.EnforceMountPolicy(tc.sandboxID, tc.containerID, tc.mountSpec)

		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid mount list")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_EnforceMountPolicy_BadDestination: %v", err)
	}
}

func Test_Rego_EnforceMountPolicy_BadType(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupRegoMountTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		index := randMinMax(testRand, 0, int32(len(tc.mountSpec.Mounts)-1))
		tc.mountSpec.Mounts[index].Type = randString(testRand, 4)

		err = tc.policy.EnforceMountPolicy(tc.sandboxID, tc.containerID, tc.mountSpec)

		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid mount list")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_EnforceMountPolicy_BadType: %v", err)
	}
}

func Test_Rego_EnforceMountPolicy_BadOption(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupRegoMountTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		mindex := 0
		//mindex := randMinMax(testRand, 0, int32(len(tc.mountSpec.Mounts)-1))

		for i, mount := range tc.mountSpec.Mounts {
			fmt.Printf("size of options for %d is %d\n", i, len(mount.Options))
		}

		tc.mountSpec.Mounts[mindex].Options[0] = randString(testRand, maxGeneratedMountOptionLength)

		//append(tc.mountSpec.Mounts[mindex].Options, randString(testRand, maxGeneratedMountOptionLength))

		err = tc.policy.EnforceMountPolicy(tc.sandboxID, tc.containerID, tc.mountSpec)

		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid mount list")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 1}); err != nil {
		t.Errorf("Test_Rego_EnforceMountPolicy_BadOption: %v", err)
	}
}
