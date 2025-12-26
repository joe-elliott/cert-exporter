package args

import (
	"testing"
)

func TestGlobArgs_String(t *testing.T) {
	args := GlobArgs{}
	if args.String() != "globargs" {
		t.Errorf("Expected String() to return 'globargs', got '%s'", args.String())
	}

	// Test with values
	args = GlobArgs{"value1", "value2"}
	if args.String() != "globargs" {
		t.Errorf("Expected String() to return 'globargs', got '%s'", args.String())
	}
}

func TestGlobArgs_Set(t *testing.T) {
	args := GlobArgs{}

	// Test setting a single value
	err := args.Set("value1")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(args) != 1 {
		t.Errorf("Expected 1 value, got %d", len(args))
	}
	if args[0] != "value1" {
		t.Errorf("Expected first value to be 'value1', got '%s'", args[0])
	}

	// Test setting multiple values
	err = args.Set("value2")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(args) != 2 {
		t.Errorf("Expected 2 values, got %d", len(args))
	}
	if args[1] != "value2" {
		t.Errorf("Expected second value to be 'value2', got '%s'", args[1])
	}

	// Test setting more values
	err = args.Set("value3")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(args) != 3 {
		t.Errorf("Expected 3 values, got %d", len(args))
	}
	if args[2] != "value3" {
		t.Errorf("Expected third value to be 'value3', got '%s'", args[2])
	}
}

func TestGlobArgs_SetEmptyString(t *testing.T) {
	args := GlobArgs{}

	err := args.Set("")
	if err != nil {
		t.Errorf("Expected no error when setting empty string, got %v", err)
	}
	if len(args) != 1 {
		t.Errorf("Expected 1 value, got %d", len(args))
	}
	if args[0] != "" {
		t.Errorf("Expected first value to be empty string, got '%s'", args[0])
	}
}

func TestGlobArgs_SetSpecialCharacters(t *testing.T) {
	args := GlobArgs{}

	// Test with glob patterns
	testValues := []string{
		"/etc/**/*.crt",
		"/var/lib/*.pem",
		"*.{crt,pem}",
		"/path/with spaces/cert.crt",
		"/path/with/unicode/☺.crt",
	}

	for _, value := range testValues {
		err := args.Set(value)
		if err != nil {
			t.Errorf("Expected no error for value '%s', got %v", value, err)
		}
	}

	if len(args) != len(testValues) {
		t.Errorf("Expected %d values, got %d", len(testValues), len(args))
	}

	for i, expected := range testValues {
		if args[i] != expected {
			t.Errorf("Expected value %d to be '%s', got '%s'", i, expected, args[i])
		}
	}
}

func TestGlobArgs_Order(t *testing.T) {
	args := GlobArgs{}

	// Test that values are appended in order
	values := []string{"first", "second", "third", "fourth"}
	for _, value := range values {
		args.Set(value)
	}

	for i, expected := range values {
		if args[i] != expected {
			t.Errorf("Expected value at index %d to be '%s', got '%s'", i, expected, args[i])
		}
	}
}
