//go:build linux
// +build linux

package securitypolicy

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"testing/quick"

	oci "github.com/opencontainers/runtime-spec/specs-go"
)

// Validate we do our conversion from Json to rego correctly
func Test_MarshalRego(t *testing.T) {
	f := func(p *generatedContainers) bool {
		base64policy, err := securityPolicyFromInternal(p.containers).EncodeToString()

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
		securityPolicy := securityPolicyFromInternal(p.containers)
		policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy, []oci.Mount{}, []oci.Mount{})
		if err != nil {
			t.Errorf("unable to convert policy to rego: %v", err)
		}

		target := testDataGenerator.uniqueMountTarget()
		rootHash := generateInvalidRootHash(testRand)

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
		securityPolicy := securityPolicyFromInternal(p.containers)
		policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy, []oci.Mount{}, []oci.Mount{})
		if err != nil {
			t.Errorf("unable to convert policy to rego: %v", err)
		}

		target := testDataGenerator.uniqueMountTarget()
		rootHash := selectRootHashFromContainers(p, testRand)

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
		securityPolicy := securityPolicyFromInternal(p.containers)
		policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy, []oci.Mount{}, []oci.Mount{})
		if err != nil {
			t.Error(err)
			return false
		}

		target := testDataGenerator.uniqueMountTarget()
		rootHash := selectRootHashFromContainers(p, testRand)

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

func Test_Rego_EnforceDeviceMountPolicy_Duplicate_Device_Target(t *testing.T) {
	f := func(p *generatedContainers) bool {
		securityPolicy := securityPolicyFromInternal(p.containers)
		policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy, []oci.Mount{}, []oci.Mount{})
		if err != nil {
			t.Errorf("unable to convert policy to rego: %v", err)
		}

		target := testDataGenerator.uniqueMountTarget()
		rootHash := selectRootHashFromContainers(p, testRand)
		err = policy.EnforceDeviceMountPolicy(target, rootHash)
		if err != nil {
			t.Error("Valid device mount failed. It shouldn't have.")
			return false
		}

		rootHash = selectRootHashFromContainers(p, testRand)
		err = policy.EnforceDeviceMountPolicy(target, rootHash)
		if err == nil {
			t.Error("Duplicate device mount target was allowed. It shouldn't have been.")
			return false
		}

		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_EnforceDeviceMountPolicy_Duplicate_Device_Target failed: %v", err)
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

// Test that an image that contains layers that share a roothash value can be
// successfully mounted. This was a failure scenario in an earlier policy engine
// implementation.
func Test_Rego_EnforceOverlayMountPolicy_Layers_With_Same_Root_Hash(t *testing.T) {

	container := generateContainersContainer(testRand, 2, maxLayersInGeneratedContainer)

	// make the last two layers have the same hash value
	numLayers := len(container.Layers)
	container.Layers[numLayers-2] = container.Layers[numLayers-1]

	securityPolicy := securityPolicyFromInternal([]*securityPolicyContainer{container})
	policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy, []oci.Mount{}, []oci.Mount{})
	if err != nil {
		t.Fatal("Unable to create security policy")
	}

	containerID := testDataGenerator.uniqueContainerID()

	layers, err := testDataGenerator.createValidOverlayForContainer(policy, container)
	if err != nil {
		t.Fatalf("error creating valid overlay: %v", err)
	}

	err = policy.EnforceOverlayMountPolicy(containerID, layers)
	if err != nil {
		t.Fatalf("Unable to create an overlay where root hashes are the same")
	}
}

// Test that can we mount overlays across containers where some layers are
// shared and on the same device. A common example of this is a base image that
// is used by many containers.
// The setup for this test is rather complicated
func Test_Rego_EnforceOverlayMountPolicy_Layers_Shared_Layers(t *testing.T) {
	containerOne := generateContainersContainer(testRand, 1, 2)
	containerTwo := generateContainersContainer(testRand, 1, 10)

	sharedLayerIndex := 0

	// Make the two containers have the same base layer
	containerTwo.Layers[sharedLayerIndex] = containerOne.Layers[sharedLayerIndex]
	containers := []*securityPolicyContainer{containerOne, containerTwo}

	securityPolicy := securityPolicyFromInternal(containers)
	policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy, []oci.Mount{}, []oci.Mount{})
	if err != nil {
		t.Fatal("Unable to create security policy")
	}

	//
	// Mount our first containers overlay. This should all work.
	//
	containerID := testDataGenerator.uniqueContainerID()

	// Create overlay
	containerOneOverlay := make([]string, len(containerOne.Layers))

	sharedMount := ""
	for i := 0; i < len(containerOne.Layers); i++ {
		mount := testDataGenerator.uniqueMountTarget()
		err := policy.EnforceDeviceMountPolicy(mount, containerOne.Layers[i])
		if err != nil {
			t.Fatalf("Unexpected error mounting overlay device: %v", err)
		}
		if i == sharedLayerIndex {
			sharedMount = mount
		}

		containerOneOverlay[len(containerOneOverlay)-i-1] = mount
	}

	err = policy.EnforceOverlayMountPolicy(containerID, containerOneOverlay)
	if err != nil {
		t.Fatalf("Unexpected error mounting overlay: %v", err)
	}

	//
	// Mount our second contaniers overlay. This should all work.
	//
	containerID = testDataGenerator.uniqueContainerID()

	// Create overlay
	containerTwoOverlay := make([]string, len(containerTwo.Layers))

	for i := 0; i < len(containerTwo.Layers); i++ {
		var mount string
		if i != sharedLayerIndex {
			mount = testDataGenerator.uniqueMountTarget()

			err := policy.EnforceDeviceMountPolicy(mount, containerTwo.Layers[i])
			if err != nil {
				t.Fatalf("Unexpected error mounting overlay device: %v", err)
			}
		} else {
			mount = sharedMount
		}

		containerTwoOverlay[len(containerTwoOverlay)-i-1] = mount
	}

	err = policy.EnforceOverlayMountPolicy(containerID, containerTwoOverlay)
	if err != nil {
		t.Fatalf("Unexpected error mounting overlay: %v", err)
	}

	// A final sanity check that we really had a shared mount
	if containerOneOverlay[len(containerOneOverlay)-1] != containerTwoOverlay[len(containerTwoOverlay)-1] {
		t.Fatal("Ooops. Looks like we botched our test setup.")
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

func Test_Rego_EnforceOverlayMountPolicy_Reusing_ID_Across_Overlays(t *testing.T) {
	var containers []*securityPolicyContainer

	for i := 0; i < 2; i++ {
		containers = append(containers, generateContainersContainer(testRand, 1, maxLayersInGeneratedContainer))
	}

	securityPolicy := securityPolicyFromInternal(containers)
	defaultMounts := generateMounts(testRand)
	privilegedMounts := generateMounts(testRand)

	policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy,
		toOCIMounts(defaultMounts),
		toOCIMounts(privilegedMounts))
	if err != nil {
		t.Fatal(err)
	}

	containerID := testDataGenerator.uniqueContainerID()

	// First usage should work
	layerPaths, err := testDataGenerator.createValidOverlayForContainer(policy, containers[0])
	if err != nil {
		t.Fatalf("Unexpected error creating valid overlay: %v", err)
	}

	err = policy.EnforceOverlayMountPolicy(containerID, layerPaths)
	if err != nil {
		t.Fatalf("Unexpected error mounting overlay filesystem: %v", err)
	}

	// Reusing container ID with another overlay should fail
	layerPaths, err = testDataGenerator.createValidOverlayForContainer(policy, containers[1])
	if err != nil {
		t.Fatalf("Unexpected error creating valid overlay: %v", err)
	}

	err = policy.EnforceOverlayMountPolicy(containerID, layerPaths)
	if err == nil {
		t.Fatalf("Unexpected success mounting overlay filesystem")
	}
}

// work directly on the internal containers
// Test that if more than 1 instance of the same image is started, that we can
// create all the overlays that are required. So for example, if there are
// 13 instances of image X that all share the same overlay of root hashes,
// all 13 should be allowed.
func Test_Rego_EnforceOverlayMountPolicy_Multiple_Instances_Same_Container(t *testing.T) {
	for containersToCreate := 13; containersToCreate <= maxContainersInGeneratedPolicy; containersToCreate++ {
		var containers []*securityPolicyContainer

		for i := 1; i <= containersToCreate; i++ {
			arg := "command " + strconv.Itoa(i)
			c := &securityPolicyContainer{
				Command: []string{arg},
				Layers:  []string{"1", "2"},
			}

			containers = append(containers, c)
		}

		securityPolicy := securityPolicyFromInternal(containers)
		policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy, []oci.Mount{}, []oci.Mount{})
		if err != nil {
			t.Fatalf("failed create enforcer")
		}

		for i := 0; i < len(containers); i++ {
			layerPaths, err := testDataGenerator.createValidOverlayForContainer(policy, containers[i])
			if err != nil {
				t.Fatal("unexpected error on test setup")
			}

			id := testDataGenerator.uniqueContainerID()
			err = policy.EnforceOverlayMountPolicy(id, layerPaths)
			if err != nil {
				t.Fatalf("failed with %d containers", containersToCreate)
			}
		}
	}
}

func Test_Rego_EnforceCommandPolicy_NoMatches(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupSimpleRegoCreateContainerTest(p)
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

		tc, err := setupRegoCreateContainerTest(gc, container)
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
		tc, err := setupSimpleRegoCreateContainerTest(p)
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
		tc, err := setupSimpleRegoCreateContainerTest(gc)
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

func Test_Rego_EnforceCreateContainer(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupSimpleRegoCreateContainerTest(p)
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

func Test_Rego_Enforce_CreateContainer_Start_All_Containers(t *testing.T) {
	f := func(p *generatedContainers) bool {
		securityPolicy := securityPolicyFromInternal(p.containers)
		defaultMounts := generateMounts(testRand)
		privilegedMounts := generateMounts(testRand)

		policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy,
			toOCIMounts(defaultMounts),
			toOCIMounts(privilegedMounts))
		if err != nil {
			t.Error(err)
			return false
		}

		for _, container := range p.containers {
			containerID, err := mountImageForContainer(policy, container)
			if err != nil {
				t.Error(err)
				return false
			}

			envList := buildEnvironmentVariablesFromContainerRules(container, testRand)

			sandboxID := generateSandboxID(testRand)
			mounts := container.Mounts
			mounts = append(mounts, defaultMounts...)
			if container.AllowElevated {
				mounts = append(mounts, privilegedMounts...)
			}
			mountSpec := buildMountSpecFromMountArray(mounts, sandboxID, testRand)

			err = policy.EnforceCreateContainerPolicy(containerID, container.Command, envList, container.WorkingDir, sandboxID, mountSpec.Mounts)

			// getting an error means something is broken
			if err != nil {
				t.Error(err)
				return false
			}
		}

		return true

	}

	if err := quick.Check(f, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("Test_Rego_Enforce_CreateContainer_Start_All_Containers: %v", err)
	}
}

func Test_Rego_EnforceCreateContainer_Invalid_ContainerID(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupSimpleRegoCreateContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		containerID := testDataGenerator.uniqueContainerID()
		err = tc.policy.EnforceCreateContainerPolicy(containerID, tc.argList, tc.envList, tc.workingDir, tc.sandboxID, tc.mounts)

		// not getting an error means something is broken
		return err != nil
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_EnforceCreateContainer_Invalid_ContainerID: %v", err)
	}
}

func Test_Rego_EnforceCreateContainer_Same_Container_Twice(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupSimpleRegoCreateContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, tc.envList, tc.workingDir, tc.sandboxID, tc.mounts)
		if err != nil {
			t.Error("Unable to start valid container.")
			return false
		}
		err = tc.policy.EnforceCreateContainerPolicy(tc.containerID, tc.argList, tc.envList, tc.workingDir, tc.sandboxID, tc.mounts)
		if err == nil {
			t.Error("Able to start a container with already used id.")
			return false
		}

		return true
	}

	if err := quick.Check(f, &quick.Config{MaxCount: 250}); err != nil {
		t.Errorf("Test_Rego_EnforceCreateContainer_Same_Container_Twice: %v", err)
	}
}

func Test_Rego_ExtendDefaultMounts(t *testing.T) {
	f := func(p *generatedContainers) bool {
		tc, err := setupSimpleRegoCreateContainerTest(p)
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
		tc, err := setupSimpleRegoCreateContainerTest(p)
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
		tc, err := setupSimpleRegoCreateContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		inputMounts := tc.mounts
		mindex := randMinMax(testRand, 0, int32(len(tc.mounts)-1))
		options := inputMounts[mindex].Options
		inputMounts[mindex].Options = options[:len(options)-1]

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
		tc, err := setupSimpleRegoCreateContainerTest(p)
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
		tc, err := setupSimpleRegoCreateContainerTest(p)
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
		tc, err := setupSimpleRegoCreateContainerTest(p)
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
		tc, err := setupSimpleRegoCreateContainerTest(p)
		if err != nil {
			t.Error(err)
			return false
		}

		mindex := randMinMax(testRand, 0, int32(len(tc.mounts)-1))
		mountToChange := tc.mounts[mindex]
		oindex := randMinMax(testRand, 0, int32(len(mountToChange.Options)-1))
		tc.mounts[mindex].Options[oindex] = randString(testRand, maxGeneratedMountOptionLength)

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

func securityPolicyFromInternal(containers []*securityPolicyContainer) *SecurityPolicy {
	securityPolicy := new(SecurityPolicy)
	securityPolicy.AllowAll = false
	securityPolicy.Containers.Length = len(containers)
	securityPolicy.Containers.Elements = make(map[string]Container)
	for i, c := range containers {
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

/**
 * NOTE_TESTCOPY: the following "copy*" functions are provided to ensure that
 * everything passed to the policy is a new object which will not be shared in
 * any way with other policy objects in other tests. In any additional fixture
 * setup routines these functions (or others like them) should be used.
 */

func copyStrings(values []string) []string {
	valuesCopy := make([]string, len(values))
	copy(valuesCopy, values)
	return valuesCopy
}

func copyMounts(mounts []oci.Mount) []oci.Mount {
	bytes, err := json.Marshal(mounts)
	if err != nil {
		panic(err)
	}

	mountsCopy := make([]oci.Mount, len(mounts))
	err = json.Unmarshal(bytes, &mountsCopy)
	if err != nil {
		panic(err)
	}

	return mountsCopy
}

type regoOverlayTestConfig struct {
	layers      []string
	containerID string
	policy      *RegoPolicy
}

func setupRegoOverlayTest(gc *generatedContainers, valid bool) (tc *regoOverlayTestConfig, err error) {
	securityPolicy := securityPolicyFromInternal(gc.containers)
	policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy, []oci.Mount{}, []oci.Mount{})
	if err != nil {
		return nil, err
	}

	containerID := testDataGenerator.uniqueContainerID()
	c := selectContainerFromContainers(gc, testRand)

	var layerPaths []string
	if valid {
		layerPaths, err = testDataGenerator.createValidOverlayForContainer(policy, c)
		if err != nil {
			return nil, fmt.Errorf("error creating valid overlay: %w", err)
		}
	} else {
		layerPaths, err = testDataGenerator.createInvalidOverlayForContainer(policy, c)
		if err != nil {
			return nil, fmt.Errorf("error creating invalid overlay: %w", err)
		}
	}

	// see NOTE_TESTCOPY
	return &regoOverlayTestConfig{
		layers:      copyStrings(layerPaths),
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

func setupSimpleRegoCreateContainerTest(gc *generatedContainers) (tc *regoContainerTestConfig, err error) {
	c := selectContainerFromContainers(gc, testRand)
	return setupRegoCreateContainerTest(gc, c)
}

func setupRegoCreateContainerTest(gc *generatedContainers, testContainer *securityPolicyContainer) (tc *regoContainerTestConfig, err error) {
	securityPolicy := securityPolicyFromInternal(gc.containers)
	defaultMounts := generateMounts(testRand)
	privilegedMounts := generateMounts(testRand)

	policy, err := NewRegoPolicyFromSecurityPolicy(securityPolicy,
		toOCIMounts(defaultMounts),
		toOCIMounts(privilegedMounts))
	if err != nil {
		return nil, err
	}

	containerID, err := mountImageForContainer(policy, testContainer)
	if err != nil {
		return nil, err
	}

	envList := buildEnvironmentVariablesFromContainerRules(testContainer, testRand)
	sandboxID := generateSandboxID(testRand)

	mounts := testContainer.Mounts
	mounts = append(mounts, defaultMounts...)
	if testContainer.AllowElevated {
		mounts = append(mounts, privilegedMounts...)
	}
	mountSpec := buildMountSpecFromMountArray(mounts, sandboxID, testRand)

	// see NOTE_TESTCOPY
	return &regoContainerTestConfig{
		envList:     copyStrings(envList),
		argList:     copyStrings(testContainer.Command),
		workingDir:  testContainer.WorkingDir,
		containerID: containerID,
		sandboxID:   sandboxID,
		mounts:      copyMounts(mountSpec.Mounts),
		policy:      policy,
	}, nil
}

func mountImageForContainer(policy *RegoPolicy, container *securityPolicyContainer) (string, error) {
	containerID := testDataGenerator.uniqueContainerID()

	layerPaths, err := testDataGenerator.createValidOverlayForContainer(policy, container)
	if err != nil {
		return "", fmt.Errorf("error creating valid overlay: %w", err)
	}

	// see NOTE_TESTCOPY
	err = policy.EnforceOverlayMountPolicy(containerID, copyStrings(layerPaths))
	if err != nil {
		return "", fmt.Errorf("error mounting filesystem: %w", err)
	}

	return containerID, nil
}

type dataGenerator struct {
	rng          *rand.Rand
	mountTargets map[string]struct{}
	containerIDs map[string]struct{}
}

func newDataGenerator(rng *rand.Rand) *dataGenerator {
	return &dataGenerator{
		rng:          rng,
		mountTargets: map[string]struct{}{},
		containerIDs: map[string]struct{}{},
	}
}

func (gen *dataGenerator) uniqueMountTarget() string {
	for {
		t := generateMountTarget(gen.rng)
		if _, ok := gen.mountTargets[t]; !ok {
			gen.mountTargets[t] = struct{}{}
			return t
		}
	}
}

func (gen *dataGenerator) uniqueContainerID() string {
	for {
		t := generateContainerID(gen.rng)
		if _, ok := gen.containerIDs[t]; !ok {
			gen.containerIDs[t] = struct{}{}
			return t
		}
	}
}

func (gen *dataGenerator) createValidOverlayForContainer(enforcer SecurityPolicyEnforcer, container *securityPolicyContainer) ([]string, error) {
	// storage for our mount paths
	overlay := make([]string, len(container.Layers))

	for i := 0; i < len(container.Layers); i++ {
		mount := gen.uniqueMountTarget()
		err := enforcer.EnforceDeviceMountPolicy(mount, container.Layers[i])
		if err != nil {
			return overlay, err
		}

		overlay[len(overlay)-i-1] = mount
	}

	return overlay, nil
}

func (gen *dataGenerator) createInvalidOverlayForContainer(enforcer SecurityPolicyEnforcer, container *securityPolicyContainer) ([]string, error) {
	method := gen.rng.Intn(3)
	if method == 0 {
		return gen.invalidOverlaySameSizeWrongMounts(enforcer, container)
	} else if method == 1 {
		return gen.invalidOverlayCorrectDevicesWrongOrderSomeMissing(enforcer, container)
	} else {
		return gen.invalidOverlayRandomJunk(enforcer, container)
	}
}

func (gen *dataGenerator) invalidOverlaySameSizeWrongMounts(enforcer SecurityPolicyEnforcer, container *securityPolicyContainer) ([]string, error) {
	// storage for our mount paths
	overlay := make([]string, len(container.Layers))

	for i := 0; i < len(container.Layers); i++ {
		mount := gen.uniqueMountTarget()
		err := enforcer.EnforceDeviceMountPolicy(mount, container.Layers[i])
		if err != nil {
			return overlay, err
		}

		// generate a random new mount point to cause an error
		overlay[len(overlay)-i-1] = gen.uniqueMountTarget()
	}

	return overlay, nil
}

func (gen *dataGenerator) invalidOverlayCorrectDevicesWrongOrderSomeMissing(enforcer SecurityPolicyEnforcer, container *securityPolicyContainer) ([]string, error) {
	if len(container.Layers) == 1 {
		// won't work with only 1, we need to bail out to another method
		return gen.invalidOverlayRandomJunk(enforcer, container)
	}
	// storage for our mount paths
	var overlay []string

	for i := 0; i < len(container.Layers); i++ {
		mount := gen.uniqueMountTarget()
		err := enforcer.EnforceDeviceMountPolicy(mount, container.Layers[i])
		if err != nil {
			return overlay, err
		}

		if gen.rng.Intn(10) != 0 {
			overlay = append(overlay, mount)
		}
	}

	return overlay, nil
}

func (gen *dataGenerator) invalidOverlayRandomJunk(enforcer SecurityPolicyEnforcer, container *securityPolicyContainer) ([]string, error) {
	// create "junk" for entry
	layersToCreate := gen.rng.Int31n(maxLayersInGeneratedContainer)
	overlay := make([]string, layersToCreate)

	for i := 0; i < int(layersToCreate); i++ {
		overlay[i] = gen.uniqueMountTarget()
	}

	// setup entirely different and "correct" expected mounting
	for i := 0; i < len(container.Layers); i++ {
		mount := gen.uniqueMountTarget()
		err := enforcer.EnforceDeviceMountPolicy(mount, container.Layers[i])
		if err != nil {
			return overlay, err
		}
	}

	return overlay, nil
}
