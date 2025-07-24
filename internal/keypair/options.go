package keypair

type Options struct {
	CABundle    string `required:"" type:"existingfile" help:"Path to the CA bundle file"`
	Certificate string `required:"" type:"existingfile" help:"Path to the certificate file"`
	Key         string `required:"" type:"existingfile" help:"Path to the key file"`
}

func (opts *Options) ListFilePaths() []string {
	rv := make([]string, 0, 3)
	rv = append(rv, opts.CABundle)
	rv = append(rv, opts.Certificate)
	rv = append(rv, opts.Key)
	return rv
}
