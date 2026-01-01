package args

import (
	"fmt"
	"strings"

	"github.com/gobwas/glob"
)

// PasswordSpec defines a glob pattern and its associated password.
type PasswordSpec struct {
	GlobPattern  string
	Password     string
	CompiledGlob glob.Glob
}

// PasswordSpecFlag is a custom flag type for collecting multiple PasswordSpec.
type PasswordSpecFlag []PasswordSpec

// String implements flag.Value
func (psf *PasswordSpecFlag) String() string {
	if psf == nil || len(*psf) == 0 {
		return ""
	}
	var parts []string
	for _, spec := range *psf {
		// Obfuscate password in string output for help messages or logging
		parts = append(parts, fmt.Sprintf("%q:%s", spec.GlobPattern, "****"))
	}
	return strings.Join(parts, ", ")
}

// Set implements flag.Value
func (psf *PasswordSpecFlag) Set(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid format for password spec. Expected 'glob:password', got %q", value)
	}
	globPattern := strings.TrimSpace(parts[0])
	password := parts[1] // Password itself might contain colons or leading/trailing spaces

	if globPattern == "" {
		return fmt.Errorf("glob pattern cannot be empty in password spec %q", value)
	}

	g, err := glob.Compile(globPattern)
	if err != nil {
		return fmt.Errorf("invalid glob pattern %q in spec %q: %w", globPattern, value, err)
	}

	*psf = append(*psf, PasswordSpec{
		GlobPattern:  globPattern,
		Password:     password,
		CompiledGlob: g,
	})
	return nil
}
