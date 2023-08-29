//go:build mage

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/sirupsen/logrus"
	"golang.org/x/term"
)

const (
	Go       = "go"
	gomobile = "gomobile"
)

// Build builds the library.
func Build() error {
	println("Building...")
	return sh.Run(Go, "build", "-tags", "jwx_es256k", "./...")
}

// Clean deletes any build artifacts.
func Clean() {
	println("Cleaning...")
	_ = os.RemoveAll("bin")
}

// Test runs unit tests without coverage.
// The mage `-v` option will trigger a verbose output of the test
func Test() error {
	return runTests()
}

func Fuzz() error {
	return runFuzzTests()
}

func runTests(extraTestArgs ...string) error {
	args := []string{"test"}
	if mg.Verbose() {
		args = append(args, "-v")
	}
	args = append(args, "-tags=jwx_es256k")
	args = append(args, extraTestArgs...)
	args = append(args, "./...")
	testEnv := map[string]string{
		"CGO_ENABLED": "1",
		"GO111MODULE": "on",
	}
	writer := ColorizeTestStdout()
	_, _ = fmt.Printf("%+v", args)
	_, err := sh.Exec(testEnv, writer, os.Stderr, Go, args...)
	return err
}

func runFuzzTests(extraTestArgs ...string) error {
	dirs := []string{"./did"}

	for _, dir := range dirs {
		functionNames, _ := getFuzzTests(dir)

		for _, testName := range functionNames {
			args := []string{"test"}
			if mg.Verbose() {
				args = append(args, "-v")
			}
			args = append(args, dir)
			args = append(args, fmt.Sprintf("-run=%s", testName))
			args = append(args, fmt.Sprintf("-fuzz=%s", testName))
			args = append(args, "-fuzztime=10s")
			testEnv := map[string]string{
				"CGO_ENABLED": "1",
				"GO111MODULE": "on",
			}
			writer := ColorizeTestStdout()
			fmt.Printf("%+v\n", args)
			_, err := sh.Exec(testEnv, writer, os.Stderr, Go, args...)
			if err != nil {
				return err
			}
		}

	}
	return nil
}

func getFuzzTests(src string) ([]string, error) {
	// src is the input for which we want to inspect the AST.
	var testFilePaths []string
	filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, "test.go") {
			return nil
		}
		testFilePaths = append(testFilePaths, path)
		return nil
	})

	// Create the AST by parsing src.
	fset := token.NewFileSet() // positions are relative to fset
	var testNames []string
	for _, filename := range testFilePaths {
		// Pass in nil to automatically parse the file
		f, err := parser.ParseFile(fset, filename, nil, 0)
		if err != nil {
			panic(err)
		}
		ast.FileExports(f)
		ast.FilterFile(f, func(s string) bool {
			p := strings.HasPrefix(s, "Fuzz")
			if p {
				testNames = append(testNames, s)
			}
			return p
		})
	}
	return testNames, nil
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
	if term.IsTerminal(syscall.Stdout) {
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
	args = append(args, "-race")
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

// Vuln downloads and runs govulncheck https://go.dev/blog/vuln
func Vuln() error {
	println("Vulnerability checks...")
	if err := installGoVulnIfNotPresent(); err != nil {
		logrus.WithError(err).Error("error installing go-vuln")
		return err
	}
	return sh.Run("govulncheck", "./...")
}

func installGoVulnIfNotPresent() error {
	return installIfNotPresent("govulncheck", "golang.org/x/vuln/cmd/govulncheck@latest")
}

func installGoMobileIfNotPresent() error {
	return installIfNotPresent(gomobile, "golang.org/x/mobile/cmd/gomobile@latest")
}

// IOS Generates the iOS packages
// Note: this command also installs "gomobile" if not present
func IOS() error {
	if err := installGoMobileIfNotPresent(); err != nil {
		logrus.WithError(err).Fatal("Error installing gomobile")
		return err
	}

	println("Building iOS...")
	bindIOS := sh.RunCmd(gomobile, "bind", "-target", "ios", "-tags", "jwx_es256k")
	return bindIOS("./mobile")
}

// Android Generates the Android packages
// Note: this command also installs "gomobile" if not present
func Android() error {
	if err := installGoMobileIfNotPresent(); err != nil {
		logrus.WithError(err).Fatal("Error installing gomobile")
		return err
	}

	apiLevel := "33"
	println("Building Android - API Level: " + apiLevel + "...")
	bindAndroid := sh.RunCmd("gomobile", "bind", "-target", "android", "-androidapi", "33", "-tags", "jwx_es256k")
	return bindAndroid("./mobile")
}
