//go:build mage

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/flowstack-com/jsonschema"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	Go              = "go"
	gomobile        = "gomobile"
	schemaDirectory = "./schema/known_schemas/"
)

// Build builds the library.
func Build() error {
	fmt.Println("Building...")
	return sh.Run(Go, "build", "-tags", "jwx_es256k", "./...")
}

// Clean deletes any build artifacts.
func Clean() {
	fmt.Println("Cleaning...")
	_ = os.RemoveAll("bin")
}

// Test runs unit tests without coverage.
// The mage `-v` option will trigger a verbose output of the test
func Test() error {
	return runTests()
}

func runTests(extraTestArgs ...string) error {
	args := []string{"test"}
	if mg.Verbose() {
		args = append(args, "-v")
	}
	args = append(args, "-race", "-tags=jwx_es256k")
	args = append(args, extraTestArgs...)
	args = append(args, "./...")
	testEnv := map[string]string{
		"CGO_ENABLED": "1",
		"GO111MODULE": "on",
	}
	writer := ColorizeTestStdout()
	fmt.Printf("%+v", args)
	_, err := sh.Exec(testEnv, writer, os.Stderr, Go, args...)
	return err
}

func Deps() error {
	return brewInstall("golangci-lint")
}

func brewInstall(formula string) error {
	return sh.Run("brew", "install", formula)
}

func Lint() error {
	return sh.Run("golangci-lint", "run")
}

func ColorizeTestOutput(w io.Writer) io.Writer {
	writer := NewRegexpWriter(w, `PASS.*`, "\033[32m$0\033[0m")
	return NewRegexpWriter(writer, `FAIL.*`, "\033[31m$0\033[0m")
}

func ColorizeTestStdout() io.Writer {
	if terminal.IsTerminal(syscall.Stdout) {
		return ColorizeTestOutput(os.Stdout)
	}
	return os.Stdout
}

type regexpWriter struct {
	inner io.Writer
	re    *regexp.Regexp
	repl  []byte
}

func NewRegexpWriter(inner io.Writer, re string, repl string) io.Writer {
	return &regexpWriter{inner, regexp.MustCompile(re), []byte(repl)}
}

func (w *regexpWriter) Write(p []byte) (int, error) {
	r := w.re.ReplaceAll(p, w.repl)
	n, err := w.inner.Write(r)
	if n > len(r) {
		n = len(r)
	}
	return n, err
}

func runGo(cmd string, args ...string) error {
	return sh.Run(findOnPathOrGoPath(Go), append([]string{"run", cmd}, args...)...)
}

// InstallIfNotPresent installs a go based tool (if not already installed)
func installIfNotPresent(execName, goPackage string) error {
	usr, err := user.Current()
	if err != nil {
		logrus.WithError(err).Fatal()
		return err
	}
	pathOfExec := findOnPathOrGoPath(execName)
	if len(pathOfExec) == 0 {
		cmd := exec.Command(Go, "get", "-u", goPackage)
		if err := runGoCommand(usr, *cmd); err != nil {
			logrus.WithError(err).Warnf("Error running command: %s", cmd.String())
			cmd = exec.Command(Go, "install", goPackage)
			if err := runGoCommand(usr, *cmd); err != nil {
				logrus.WithError(err).Fatalf("Error running command: %s", cmd.String())
				return err
			}
		}
		logrus.Infof("Successfully installed %s", goPackage)
	}
	return nil
}

func runGoCommand(usr *user.User, cmd exec.Cmd) error {
	cmd.Dir = usr.HomeDir
	if err := cmd.Start(); err != nil {
		logrus.WithError(err).Fatalf("Error running command: %s", cmd.String())
		return err
	}
	return cmd.Wait()
}

func findOnPathOrGoPath(execName string) string {
	if p := findOnPath(execName); p != "" {
		return p
	}
	p := filepath.Join(goPath(), "bin", execName)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	fmt.Printf("Could not find %s on PATH or in GOPATH/bin\n", execName)
	return ""
}

func findOnPath(execName string) string {
	pathEnv := os.Getenv("PATH")
	pathDirectories := strings.Split(pathEnv, string(os.PathListSeparator))
	for _, pathDirectory := range pathDirectories {
		possible := filepath.Join(pathDirectory, execName)
		stat, err := os.Stat(possible)
		if err == nil || os.IsExist(err) {
			if (stat.Mode() & 0111) != 0 {
				return possible
			}
		}
	}
	return ""
}

func goPath() string {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
		return ""
	}
	goPath, goPathSet := os.LookupEnv("GOPATH")
	if !goPathSet {
		goPath = filepath.Join(usr.HomeDir, Go)
	}
	return goPath
}

// CBT runs clean; build; test
func CBT() error {
	Clean()
	if err := Build(); err != nil {
		return err
	}
	if err := Test(); err != nil {
		return err
	}
	return nil
}

// CITest runs unit tests with coverage as a part of CI.
// The mage `-v` option will trigger a verbose output of the test
func CITest() error {
	return runCITests()
}

func runCITests(extraTestArgs ...string) error {
	args := []string{"test"}
	if mg.Verbose() {
		args = append(args, "-v")
	}
	args = append(args, "-tags=jwx_es256k")
	args = append(args, "-covermode=atomic")
	args = append(args, "-coverprofile=coverage.out")
	args = append(args, extraTestArgs...)
	args = append(args, "./...")
	testEnv := map[string]string{
		"CGO_ENABLED": "1",
		"GO111MODULE": "on",
	}
	writer := ColorizeTestStdout()
	fmt.Printf("%+v", args)
	_, err := sh.Exec(testEnv, writer, os.Stderr, Go, args...)
	return err
}

func installGoMobileIfNotPresent() error {
	return installIfNotPresent(gomobile, "golang.org/x/mobile/cmd/gomobile@latest")
}

// Mobile runs gomobile commands on specified packages for both Android and iOS
func Mobile() {
	pkgs := []string{"crypto", "did", "cryptosuite"}
	if err := IOS(pkgs...); err != nil {
		logrus.WithError(err).Error("Error building iOS")
		return
	}
	if err := Android(pkgs...); err != nil {
		logrus.WithError(err).Error("Error building Android")
		return
	}
}

// IOS Generates the iOS packages
// Note: this command also installs "gomobile" if not present
func IOS(pkgs ...string) error {
	if err := installGoMobileIfNotPresent(); err != nil {
		logrus.WithError(err).Fatal("Error installing gomobile")
		return err
	}

	fmt.Println("Building iOS...")
	bindIOS := sh.RunCmd(gomobile, "bind", "-target", "ios")

	for _, pkg := range pkgs {
		fmt.Printf("Building [%s] package...\n", pkg)
		if err := bindIOS(pkg); err != nil {
			logrus.WithError(err).Fatal("Error building iOS pkg: %s", pkg)
			return err
		}
	}

	return nil
}

// Android Generates the Android packages
// Note: this command also installs "gomobile" if not present
func Android(pkgs ...string) error {
	if err := installGoMobileIfNotPresent(); err != nil {
		logrus.WithError(err).Fatal("Error installing gomobile")
		return err
	}

	apiLevel := "23"
	fmt.Println("Building Android - API Level: " + apiLevel + "...")
	bindAndroid := sh.RunCmd("gomobile", "bind", "-target", "android", "-androidapi", "23")

	for _, pkg := range pkgs {
		fmt.Printf("Building [%s] package...\n", pkg)
		if err := bindAndroid(pkg); err != nil {
			logrus.WithError(err).Fatal("Error building iOS pkg: %s", pkg)
			return err
		}
	}

	return nil
}

// Vuln downloads and runs govulncheck https://go.dev/blog/vuln
func Vuln() error {
	fmt.Println("Vulnerability checks...")
	if err := installGoVulnIfNotPresent(); err != nil {
		fmt.Printf("Error installing go-vuln: %s", err.Error())
		return err
	}
	return sh.Run("govulncheck", "./...")
}

func installGoVulnIfNotPresent() error {
	return installIfNotPresent("govulncheck", "golang.org/x/vuln/cmd/govulncheck@latest")
}

// DerefSchemas takes our known schemas and dereferences the schema's $ref http links to be a part of the json schema object.
// This makes our code faster when doing validation checks and allows us to not ping outside sources for schemas refs which may go down or change.
// TODO: (Neal) Currently we do not use these dereferenced schemas in code because there is more work to be done here.
// Currently these dereferenced schemas are missing some information and fail validation with our known json objects
// I believe some more work in the investigation library needs to be done and we need to handle circular dependencies
func DerefSchemas() error {
	files, err := ioutil.ReadDir(schemaDirectory)
	if err != nil {
		logrus.WithError(err).Fatal("problem reading directory at: " + schemaDirectory)
		return err
	}

	os.Chmod(schemaDirectory, 0777)

	for _, file := range files {

		// dont deref already deref'd json schemas
		if strings.Contains(file.Name(), "-deref") {
			continue
		}

		logrus.Println("dereferenceing file at: " + file.Name())

		fileBytes, err := os.ReadFile(schemaDirectory + file.Name())
		if err != nil {
			logrus.WithError(err).Fatal("problem reading file at: " + schemaDirectory + file.Name())
			continue
		}

		sch, err := jsonschema.New(fileBytes)
		if err != nil {
			logrus.WithError(err).Fatal("problem creating schema")
			continue
		}

		// dereference schema
		err = sch.DeRef()
		if err != nil {
			logrus.WithError(err).Fatal("problem dereferenceing schema")
			continue
		}

		schemaBytes, err := sch.MarshalJSON()
		if err != nil {
			logrus.WithError(err).Fatal("problem marshalling schema json")
			continue
		}

		err = os.WriteFile("./schema/known_schemas/"+strings.ReplaceAll(file.Name(), ".json", "")+"-deref.json", schemaBytes, 0644)
		if err != nil {
			logrus.WithError(err).Fatal("problem writing deref json to file")
			continue
		}

	}
	logrus.Println("\n\nFinished dereferenceing schemas")
	return nil
}
