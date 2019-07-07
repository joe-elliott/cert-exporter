package args

type GlobArgs []string

func (i *GlobArgs) String() string {
	return "test"
}

func (i *GlobArgs) Set(value string) error {
	*i = append(*i, value)
	return nil
}
