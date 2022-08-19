//go:build linux && rego
// +build linux,rego

package securitypolicy

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/Microsoft/hcsshim/internal/guest/spec"
	"github.com/Microsoft/hcsshim/internal/guestpath"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown"
	oci "github.com/opencontainers/runtime-spec/specs-go"
)

const regoEnforcer = "rego"

func init() {
	registeredEnforcers[regoEnforcer] = createRegoEnforcer
	// Overriding the value inside init guarantees that this assignment happens
	// after the variable has been initialized in securitypolicy.go and there
	// are no race conditions. When multiple init functions are defined in a
	// single package, the order of their execution is determined by the
	// filename.
	defaultEnforcer = regoEnforcer
}

//go:embed framework.rego
var FrameworkCode string

//go:embed policy.rego
var PolicyCode string

var Indent string = "    "

// RegoEnforcer is a stub implementation of a security policy, which will be
// based on [Rego] policy language. The detailed implementation will be
// introduced in the subsequent PRs and documentation updated accordingly.
//
// [Rego]: https://www.openpolicyagent.org/docs/latest/policy-language/
type RegoEnforcer struct {
	// Rego which describes policy behavior (see above)
	behavior string
	// Rego which describes policy objects (containers, etc.)
	objects string
	// Mutex to prevent concurrent access to fields
	mutex *sync.Mutex
	// Rego data object, used to store policy state
	data map[string]interface{}
	// Base64 encoded (JSON) policy
	base64policy string
	// Compiled modules
	compiledModules *ast.Compiler
}

type securityPolicyInternal struct {
	AllowAll   bool
	Containers []*securityPolicyContainer
}

func (sp SecurityPolicy) toInternal() (*securityPolicyInternal, error) {
	policy := new(securityPolicyInternal)
	var err error
	if policy.Containers, err = sp.Containers.toInternal(); err != nil {
		return nil, err
	}

	return policy, nil
}

func toOptions(values []string) Options {
	elements := make(map[string]string)
	for i, value := range values {
		elements[fmt.Sprint(i)] = value
	}
	return Options{
		Length:   len(values),
		Elements: elements,
	}
}

func (mounts *Mounts) Append(other []oci.Mount) {
	start := mounts.Length
	for i, mount := range other {
		mounts.Elements[fmt.Sprint(i+start)] = Mount{
			Source:      mount.Source,
			Destination: mount.Destination,
			Type:        mount.Type,
			Options:     toOptions(mount.Options),
		}
	}

	mounts.Length += len(other)
}

type StringArray []string

func (array StringArray) MarshalRego() string {
	values := make([]string, len(array))
	for i, value := range array {
		values[i] = fmt.Sprintf("\"%s\"", value)
	}

	return fmt.Sprintf("[%s]", strings.Join(values, ","))
}

func writeCommand(builder *strings.Builder, command []string, indent string) error {
	array := (StringArray(command)).MarshalRego()
	_, err := builder.WriteString(fmt.Sprintf("%s\"command\": %s,\n", indent, array))
	return err
}

func (e EnvRuleConfig) MarshalRego() string {
	return fmt.Sprintf("{\"pattern\": \"%s\", \"strategy\": \"%s\"}", e.Rule, e.Strategy)
}

type EnvRuleArray []EnvRuleConfig

func (array EnvRuleArray) MarshalRego() string {
	values := make([]string, len(array))
	for i, env := range array {
		values[i] = env.MarshalRego()
	}

	return fmt.Sprintf("[%s]", strings.Join(values, ","))
}

func writeEnvRules(builder *strings.Builder, envRules []EnvRuleConfig, indent string) error {
	_, err := builder.WriteString(fmt.Sprintf("%s\"env_rules\": %s,\n", indent, EnvRuleArray(envRules).MarshalRego()))
	return err
}

func writeLayers(builder *strings.Builder, layers []string, indent string) error {
	array := (StringArray(layers)).MarshalRego()
	_, err := builder.WriteString(fmt.Sprintf("%s\"layers\": %s,\n", indent, array))
	return err
}

func (p containerProcess) MarshalRego() string {
	command := StringArray(p.command).MarshalRego()
	envRules := EnvRuleArray(p.envRules).MarshalRego()
	return fmt.Sprintf("{\"command\": %s, \"env_rules\": %s, \"working_dir\": \"%s\"}", command, envRules, p.workingDir)
}

func writeExecProcesses(builder *strings.Builder, execProcesses []containerProcess, indent string) error {
	values := make([]string, len(execProcesses))
	for i, process := range execProcesses {
		values[i] = process.MarshalRego()
	}
	_, err := builder.WriteString(fmt.Sprintf("%s\"exec_processes\": [%s],\n", indent, strings.Join(values, ",")))
	return err
}

func (m mountInternal) MarshalRego() string {
	options := StringArray(m.Options).MarshalRego()
	return fmt.Sprintf("{\"destination\": \"%s\", \"options\": %s, \"source\": \"%s\", \"type\": \"%s\"}", m.Destination, options, m.Source, m.Type)
}

func writeMounts(builder *strings.Builder, mounts []mountInternal, indent string) error {
	values := make([]string, len(mounts))
	for i, mount := range mounts {
		values[i] = mount.MarshalRego()
	}

	_, err := builder.WriteString(fmt.Sprintf("%s\"mounts\": [%s],\n", indent, strings.Join(values, ",")))
	return err
}

func writeContainer(builder *strings.Builder, container *securityPolicyContainer, indent string) error {
	if _, err := builder.WriteString(fmt.Sprintf("%s{\n", indent)); err != nil {
		return err
	}

	if err := writeCommand(builder, container.Command, indent+Indent); err != nil {
		return err
	}

	if err := writeEnvRules(builder, container.EnvRules, indent+Indent); err != nil {
		return err
	}

	if err := writeLayers(builder, container.Layers, indent+Indent); err != nil {
		return err
	}

	if err := writeMounts(builder, container.Mounts, indent+Indent); err != nil {
		return err
	}

	if err := writeExecProcesses(builder, container.ExecProcesses, indent+Indent); err != nil {
		return err
	}

	if _, err := builder.WriteString(fmt.Sprintf("%s\"allow_elevated\": %v,\n", indent+Indent, container.AllowElevated)); err != nil {
		return err
	}

	if _, err := builder.WriteString(fmt.Sprintf("%s\"working_dir\": \"%s\"\n", indent+Indent, container.WorkingDir)); err != nil {
		return err
	}

	if _, err := builder.WriteString(fmt.Sprintf("%s}", indent)); err != nil {
		return err
	}

	return nil
}

func addContainers(builder *strings.Builder, containers []*securityPolicyContainer) error {
	if _, err := builder.WriteString("containers := [\n"); err != nil {
		return err
	}

	for i, container := range containers {
		if err := writeContainer(builder, container, Indent); err != nil {
			return err
		}

		var end string
		if i < len(containers)-1 {
			end = ",\n"
		} else {
			end = "\n"
		}

		if _, err := builder.WriteString(end); err != nil {
			return err
		}
	}

	if _, err := builder.WriteString("]\n"); err != nil {
		return err
	}

	return nil
}

func (p securityPolicyInternal) MarshalRego() (string, error) {
	builder := new(strings.Builder)
	if _, err := builder.WriteString(fmt.Sprintf("package policy\nallow_all := %v\n", p.AllowAll)); err != nil {
		return "", err
	}

	if err := addContainers(builder, p.Containers); err != nil {
		return "", err
	}

	return builder.String(), nil
}

func createRegoEnforcer(state SecurityPolicyState, defaultMounts []oci.Mount, privilegedMounts []oci.Mount) (SecurityPolicyEnforcer, error) {
	if policy, err := state.SecurityPolicy.toInternal(); err == nil {
		regoPolicy, err := newRegoPolicyFromInternal(policy, defaultMounts, privilegedMounts)
		if err != nil {
			regoPolicy.base64policy = state.EncodedSecurityPolicy.SecurityPolicy
			return regoPolicy, nil
		} else {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("error converting to internal format: %w", err)
	}
}

func newRegoPolicyFromInternal(securityPolicy *securityPolicyInternal, defaultMounts []oci.Mount, privilegedMounts []oci.Mount) (*RegoEnforcer, error) {
	policy := new(RegoEnforcer)
	policy.behavior = PolicyCode
	if code, err := securityPolicy.MarshalRego(); err == nil {
		policy.objects = code
	} else {
		return nil, fmt.Errorf("failed to convert json to rego: %w", err)
	}

	policy.data = map[string]interface{}{
		"started":         []string{},
		"defaultMounts":   []interface{}{},
		"sandboxPrefix":   guestpath.SandboxMountPrefix,
		"hugePagesPrefix": guestpath.HugePagesMountPrefix,
	}
	policy.mutex = new(sync.Mutex)
	policy.base64policy = ""

	modules := map[string]string{
		"behavior.rego":  policy.behavior,
		"objects.rego":   policy.objects,
		"framework.rego": FrameworkCode,
	}

	policy.ExtendDefaultMounts(defaultMounts)
	policy.ExtendDefaultMounts(privilegedMounts)

	// TODO temporary hack for debugging policies until GCS logging design
	// and implementation is finalized. This option should be changed to
	// "true" if debugging is desired.
	options := ast.CompileOpts{
		EnablePrintStatements: false,
	}

	if compiled, err := ast.CompileModulesWithOpt(modules, options); err == nil {
		policy.compiledModules = compiled
	} else {
		return nil, fmt.Errorf("rego compilation failed: %w", err)
	}

	return policy, nil
}

func (policy RegoEnforcer) Query(input map[string]interface{}) (rego.ResultSet, error) {
	store := inmem.NewFromObject(policy.data)

	var buf bytes.Buffer
	rule := input["name"].(string)
	query := rego.New(
		rego.Query(fmt.Sprintf("data.policy.%s", rule)),
		rego.Compiler(policy.compiledModules),
		rego.Input(input),
		rego.Store(store),
		rego.PrintHook(topdown.NewPrintHook(&buf)))

	ctx := context.Background()
	results, err := query.Eval(ctx)
	if err != nil {
		fmt.Println("Policy", policy.objects)
		fmt.Println(err)
		return results, err
	}

	output := buf.String()
	if len(output) > 0 {
		fmt.Println(output)
	}

	return results, nil
}

func (policy *RegoEnforcer) EnforceDeviceMountPolicy(target string, deviceHash string) error {
	policy.mutex.Lock()
	defer policy.mutex.Unlock()

	input := map[string]interface{}{
		"name":       "mount_device",
		"target":     target,
		"deviceHash": deviceHash,
	}
	result, err := policy.Query(input)
	if err != nil {
		return err
	}

	if result.Allowed() {
		if devices, found := policy.data["devices"]; found {
			deviceMap := devices.(map[string]string)
			if _, e := deviceMap[target]; e {
				return fmt.Errorf("device %s already mounted", target)
			}
			deviceMap[target] = deviceHash
		} else {
			policy.data["devices"] = map[string]string{target: deviceHash}
		}
		return nil
	} else {
		return errors.New("device mount not allowed by policy")
	}
}

func (policy *RegoEnforcer) EnforceOverlayMountPolicy(containerID string, layerPaths []string) error {
	policy.mutex.Lock()
	defer policy.mutex.Unlock()

	input := map[string]interface{}{
		"name":        "mount_overlay",
		"containerID": containerID,
		"layerPaths":  layerPaths,
	}
	result, err := policy.Query(input)
	if err != nil {
		return err
	}

	if result.Allowed() {
		// we store the mapping of container ID -> layerPaths for later
		// use in EnforceCreateContainerPolicy here.
		if containers, found := policy.data["containers"]; found {
			containerMap := containers.(map[string]interface{})
			if _, found := containerMap[containerID]; found {
				return fmt.Errorf("container %s already mounted", containerID)
			} else {
				containerMap[containerID] = map[string]interface{}{
					"containerID": containerID,
					"layerPaths":  layerPaths,
				}
			}
		} else {
			policy.data["containers"] = map[string]interface{}{
				containerID: map[string]interface{}{
					"containerID": containerID,
					"layerPaths":  layerPaths,
				},
			}
		}
		return nil
	} else {
		return errors.New("overlay mount not allowed by policy")
	}
}

func (policy *RegoEnforcer) EnforceCreateContainerPolicy(containerID string,
	argList []string,
	envList []string,
	workingDir string,
	sandboxID string,
	mounts []oci.Mount,
) error {
	policy.mutex.Lock()
	defer policy.mutex.Unlock()

	// first, we need to obtain the overlay filestytem information
	// which was stored in EnforceOverlayMountPolicy
	var containerInfo map[string]interface{}
	if containers, found := policy.data["containers"]; found {
		containerMap := containers.(map[string]interface{})
		if container, found := containerMap[containerID]; found {
			containerInfo = container.(map[string]interface{})
		} else {
			return fmt.Errorf("container %s does not have a filesystem", containerID)
		}
	} else {
		return fmt.Errorf("container %s does not have a filesystem", containerID)
	}

	input := map[string]interface{}{
		"name":         "create_container",
		"argList":      argList,
		"envList":      envList,
		"workingDir":   workingDir,
		"sandboxDir":   spec.SandboxMountsDir(sandboxID),
		"hugePagesDir": spec.HugePagesMountsDir(sandboxID),
		"mounts":       mounts,
	}

	// this adds the overlay layerPaths array to the input
	for key, value := range containerInfo {
		input[key] = value
	}

	result, err := policy.Query(input)
	if err != nil {
		return err
	}

	if result.Allowed() {
		started := policy.data["started"].([]string)
		policy.data["started"] = append(started, containerID)
		containerInfo["argList"] = argList
		containerInfo["envList"] = envList
		containerInfo["workingDir"] = workingDir
		containerInfo["sandboxDir"] = input["sandboxDir"]
		containerInfo["hugePagesDir"] = input["hugePagesDir"]
		containerInfo["mounts"] = mounts
		return nil
	} else {
		input["name"] = "reason"
		input["rule"] = "create_container"
		result, err := policy.Query(input)
		if err != nil {
			return err
		}

		reasons := []string{}
		for _, reason := range result[0].Expressions[0].Value.([]interface{}) {
			reasons = append(reasons, reason.(string))
		}
		return fmt.Errorf("container creation not allowed by policy. Reasons: [%s]", strings.Join(reasons, ","))
	}
}

func (policy *RegoEnforcer) EnforceDeviceUnmountPolicy(unmountTarget string) error {
	policy.mutex.Lock()
	defer policy.mutex.Unlock()

	devices := policy.data["devices"].(map[string]string)
	delete(devices, unmountTarget)

	return nil
}

func (policy *RegoEnforcer) ExtendDefaultMounts(mounts []oci.Mount) error {
	policy.mutex.Lock()
	defer policy.mutex.Unlock()

	defaultMounts := policy.data["defaultMounts"].([]interface{})
	for _, mount := range mounts {
		defaultMounts = append(defaultMounts, map[string]interface{}{
			"destination": mount.Destination,
			"source":      mount.Source,
			"options":     mount.Options,
			"type":        mount.Type,
		})
	}
	policy.data["defaultMounts"] = defaultMounts
	return nil
}

func (policy *RegoEnforcer) EncodedSecurityPolicy() string {
	return policy.base64policy
}

func (policy *RegoEnforcer) EnforceExecInContainerPolicy(containerID string, argList []string, envList []string, workingDir string) error {
	policy.mutex.Lock()
	defer policy.mutex.Unlock()

	// first, we need to obtain the overlay filestytem information
	// which was stored in EnforceOverlayMountPolicy
	var containerInfo map[string]interface{}
	if containers, found := policy.data["containers"]; found {
		containerMap := containers.(map[string]interface{})
		if container, found := containerMap[containerID]; found {
			containerInfo = container.(map[string]interface{})
		} else {
			return fmt.Errorf("container %s not started", containerID)
		}
	} else {
		return fmt.Errorf("container %s not started", containerID)
	}

	input := make(map[string]interface{})

	// this adds the overlay layerPaths array to the input
	for key, value := range containerInfo {
		input[key] = value
	}

	input["name"] = "exec_in_container"
	input["argList"] = argList
	input["envList"] = envList
	input["workingDir"] = workingDir

	result, err := policy.Query(input)
	if err != nil {
		return err
	}

	if result.Allowed() {
		return nil
	} else {
		input["name"] = "reason"
		input["rule"] = "exec_in_container"
		result, err := policy.Query(input)
		if err != nil {
			return err
		}

		reasons := []string{}
		for _, reason := range result[0].Expressions[0].Value.([]interface{}) {
			reasons = append(reasons, reason.(string))
		}
		return fmt.Errorf("exec in container not allowed by policy. Reasons: [%s]", strings.Join(reasons, ","))
	}
}
