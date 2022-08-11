//go:build linux
// +build linux

package securitypolicy

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"testing/quick"
	"time"

	oci "github.com/opencontainers/runtime-spec/specs-go"
)

// Validate we do our conversion from Json to rego correctly
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

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_EnforceDeviceMountPolicy_No_Matches failed: %v", err)
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

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_EnforceDeviceMountPolicy_Matches failed: %v", err)
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

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_EnforceDeviceUmountPolicy_Removes_Device_Entries failed: %v", err)
	}
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

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
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

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_EnforceOverlayMountPolicy_Matches: %v", err)
	}
}

// Tests the specific case of trying to mount the same overlay twice using the
// same container id. This should be disallowed.
func Test_Rego_EnforceOverlayMountPolicy_Overlay_Single_Container_Twice(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupRegoOverlayTest(p, true)
		if err != nil {
			t.Error(err)
			return false
		}

		if err := tc.policy.EnforceOverlayMountPolicy(tc.containerID, tc.layers); err != nil {
			t.Fatalf("expected nil error got: %v", err)
		}

		if err := tc.policy.EnforceOverlayMountPolicy(tc.containerID, tc.layers); err == nil {
			t.Fatalf("able to create overlay for the same container twice")
			return false
		}

		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_EnforceOverlayMountPolicy_Overlay_Single_Container_Twice: %v", err)
	}
}

// TODO: to make this work, we need a constructor that can
// work directly on the internal containers
// Test that if more than 1 instance of the same image is started, that we can
// create all the overlays that are required. So for example, if there are
// 13 instances of image X that all share the same overlay of root hashes,
// all 13 should be allowed.
func Test_Rego_EnforceOverlayMountPolicy_Multiple_Instances_Same_Container(t *testing.T) {
	for containersToCreate := 2; containersToCreate <= maxContainersInGeneratedPolicy; containersToCreate++ {
		var containers []*securityPolicyContainer

		for i := 1; i <= containersToCreate; i++ {
			arg := "command " + strconv.Itoa(i)
			c := &securityPolicyContainer{
				Command: []string{arg},
				Layers:  []string{"1", "2"},
			}

			containers = append(containers, c)
		}

		sp := NewStandardSecurityPolicyEnforcer(containers, "")

		idsUsed := map[string]bool{}
		for i := 0; i < len(containers); i++ {
			layerPaths, err := createValidOverlayForContainer(sp, containers[i], testRand)
			if err != nil {
				t.Fatal("unexpected error on test setup")
			}

			idUnique := false
			var id string
			for idUnique == false {
				id = generateContainerID(testRand)
				_, found := idsUsed[id]
				idUnique = !found
				idsUsed[id] = true
			}
			err = sp.EnforceOverlayMountPolicy(id, layerPaths)
			if err != nil {
				t.Fatalf("failed with %d containers", containersToCreate)
			}
		}
	}
}

func Test_Rego_EnforceCommandPolicy_NoMatches(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupSimpleRegoContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, generateCommand(testRand), tc.envList, tc.workingDir, tc.sandboxID, tc.mounts)

		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid command")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_EnforceCommandPolicy_NoMatches: %v", err)
	}
}

func Test_Rego_EnforceEnvironmentVariablePolicy_Re2Match(t *testing.T) {
	testFunc := func(gc *generatedContainers) bool {
		container := selectContainerFromContainers(gc, testRand)
		// add a rule to re2 match
		re2MatchRule := EnvRuleConfig{
			Strategy: EnvVarRuleRegex,
			Rule:     "PREFIX_.+=.+",
		}

		container.EnvRules = append(container.EnvRules, re2MatchRule)

		tc, err := setupRegoContainerTest(gc, container)
		if err != nil {
			t.Error(err)
			return false
		}

		envList := append(tc.envList, "PREFIX_FOO=BAR")
		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, envList, tc.workingDir, tc.sandboxID, tc.mounts)

		// getting an error means something is broken
		if err != nil {
			t.Errorf("Expected container setup to be allowed. It wasn't: %v", err)
			return false
		}

		return true
	}

	if err := quick.Check(testFunc, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_EnforceEnvironmentVariablePolicy_Re2Match: %v", err)
	}
}

func Test_Rego_EnforceEnvironmentVariablePolicy_NotAllMatches(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupSimpleRegoContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		envList := append(tc.envList, generateNeverMatchingEnvironmentVariable(testRand))
		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, envList, tc.workingDir, tc.sandboxID, tc.mounts)

		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid env list")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_EnforceEnvironmentVariablePolicy_NotAllMatches: %v", err)
	}
}

func Test_Rego_WorkingDirectoryPolicy_NoMatches(t *testing.T) {
	testFunc := func(gc *generatedContainers) bool {
		tc, err := setupSimpleRegoContainerTest(gc)
		if err != nil {
			t.Error(err)
			return false
		}

		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, tc.envList, randString(testRand, 20), tc.sandboxID, tc.mounts)
		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid working directory")
	}

	if err := quick.Check(testFunc, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_WorkingDirectoryPolicy_NoMatches: %v", err)
	}
}

// TODO
func Test_Rego_Overlay_Duplicate_Layers(t *testing.T) {
	return
}

func Test_Rego_EnforceCreateContainer(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupSimpleRegoContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, tc.envList, tc.workingDir, tc.sandboxID, tc.mounts)

		// getting an error means something is broken
		return err == nil
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_EnforceCreateContainer: %v", err)
	}
}

func Test_Rego_ExtendDefaultMounts(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupSimpleRegoContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		defaultMounts := generateMounts(testRand)
		tc.policy.ExtendDefaultMounts(toOCIMounts(defaultMounts))

		additionalMounts := buildMountSpecFromMountArray(defaultMounts, tc.sandboxID, testRand)
		tc.mounts = append(tc.mounts, additionalMounts.Mounts...)

		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, tc.envList, tc.workingDir, tc.sandboxID, tc.mounts)

		if err != nil {
			t.Error(err)
			return false
		} else {
			return true
		}
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_ExtendDefaultMounts: %v", err)
	}
}

func Test_Rego_MountPolicy_NoMatches(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupSimpleRegoContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		invalidMounts := generateMounts(testRand)
		additionalMounts := buildMountSpecFromMountArray(invalidMounts, tc.sandboxID, testRand)
		tc.mounts = append(tc.mounts, additionalMounts.Mounts...)

		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, tc.envList, tc.workingDir, tc.sandboxID, tc.mounts)

		// not getting an error means something is broken
		if err == nil {
			t.Error("We added additional mounts not in policyS and it didn't result in an error")
			return false
		}

		return strings.Contains(err.Error(), "invalid mount list")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_MountPolicy_NoMatches: %v", err)
	}
}

func Test_Rego_MountPolicy_NotAllOptionsFromConstraints(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupSimpleRegoContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		input_mounts := tc.mounts
		mindex := randMinMax(testRand, 0, int32(len(tc.mounts)-1))
		options := input_mounts[mindex].Options
		input_mounts[mindex].Options = options[:len(options)-1]

		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, tc.envList, tc.workingDir, tc.sandboxID, tc.mounts)

		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid mount list")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_MountPolicy_NotAllOptionsFromConstraints: %v", err)
	}
}

func Test_Rego_MountPolicy_BadSource(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupSimpleRegoContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		index := randMinMax(testRand, 0, int32(len(tc.mounts)-1))
		tc.mounts[index].Source = randString(testRand, maxGeneratedMountSourceLength)

		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, tc.envList, tc.workingDir, tc.sandboxID, tc.mounts)

		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid mount list")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_MountPolicy_BadSource: %v", err)
	}
}

func Test_Rego_MountPolicy_BadDestination(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupSimpleRegoContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		index := randMinMax(testRand, 0, int32(len(tc.mounts)-1))
		tc.mounts[index].Destination = randString(testRand, maxGeneratedMountDestinationLength)

		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, tc.envList, tc.workingDir, tc.sandboxID, tc.mounts)

		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid mount list")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_MountPolicy_BadDestination: %v", err)
	}
}

func Test_Rego_MountPolicy_BadType(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupSimpleRegoContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		index := randMinMax(testRand, 0, int32(len(tc.mounts)-1))
		tc.mounts[index].Type = randString(testRand, 4)

		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, tc.envList, tc.workingDir, tc.sandboxID, tc.mounts)

		// not getting an error means something is broken
		if err == nil {
			return false
		}

		return strings.Contains(err.Error(), "invalid mount list")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_MountPolicy_BadType: %v", err)
	}
}

func Test_Rego_MountPolicy_BadOption(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupSimpleRegoContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		mindex := randMinMax(testRand, 0, int32(len(tc.mounts)-1))
		mount_to_change := tc.mounts[mindex]
		oindex := randMinMax(testRand, 0, int32(len(mount_to_change.Options)-1))
		new_options := make([]string, len(mount_to_change.Options))
		for i := 0; i < len(mount_to_change.Options); i++ {
			if int32(i) != oindex {
				new_options[i] = mount_to_change.Options[i]
			} else {
				new_options[i] = randString(testRand, maxGeneratedMountOptionLength)
			}
		}
		tc.mounts[mindex].Options = new_options

		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, tc.envList, tc.workingDir, tc.sandboxID, tc.mounts)

		// not getting an error means something is broken
		if err == nil {
			t.Error("We changed a mount option and it didn't result in an error")
			return false
		}

		return strings.Contains(err.Error(), "invalid mount list")
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_MountPolicy_BadOption: %v", err)
	}
}

//
// Setup and "fixtures" follow...
//

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
	sandboxID   string
	mounts      []oci.Mount
	policy      *RegoPolicy
}

func setupSimpleRegoContainerTest(gc *generatedContainers) (tc *regoContainerTestConfig, err error) {
	c := selectContainerFromContainers(gc, testRand)
	return setupRegoContainerTest(gc, c)
}

func setupRegoContainerTest(gc *generatedContainers, activate *securityPolicyContainer) (tc *regoContainerTestConfig, err error) {
	securityPolicy := securityPolicyFromInternal(gc)
	defaultMounts := generateMounts(testRand)
	privilegedMounts := generateMounts(testRand)

	policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy,
		toOCIMounts(defaultMounts),
		toOCIMounts(privilegedMounts))
	if err != nil {
		return nil, err
	}

	containerID := generateContainerID(testRand)

	layerPaths, err := createValidOverlayForContainer(policy, activate, testRand)
	if err != nil {
		return nil, fmt.Errorf("error creating valid overlay: %w", err)
	}

	err = policy.EnforceOverlayMountPolicy(containerID, layerPaths)
	if err != nil {
		return nil, fmt.Errorf("error mounting filesystem: %w", err)
	}

	envList := buildEnvironmentVariablesFromContainerRules(activate, testRand)
	sandboxID := generateSandboxID(testRand)

	mounts := activate.Mounts
	mounts = append(mounts, defaultMounts...)
	if activate.AllowElevated {
		mounts = append(mounts, privilegedMounts...)
	}
	mount_spec := buildMountSpecFromMountArray(mounts, sandboxID, testRand)

	return &regoContainerTestConfig{
		envList:     envList,
		argList:     activate.Command,
		workingDir:  activate.WorkingDir,
		containerID: containerID,
		sandboxID:   sandboxID,
		mounts:      mount_spec.Mounts,
		policy:      policy,
	}, nil

}
