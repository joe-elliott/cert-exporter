package args

// GlobArgs is a string slice to store multiple command line args in
type GlobArgs []string

func (i *GlobArgs) String() string {
	return "globargs"
}

// Set appends a value to the GlobArgs slice
func (i *GlobArgs) Set(value string) error {
	*i = append(*i, value)
	return nil
}
