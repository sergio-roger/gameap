package certificates

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/gameap/gameap/internal/files"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_Root(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(fm *files.InMemoryFileManager)
		wantErr bool
	}{
		{
			name: "root_certificate_does_not_exist_generates_new",
			setup: func(_ *files.InMemoryFileManager) {
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm := files.NewInMemoryFileManager()
			tt.setup(fm)

			service := NewService(fm)
			ctx := context.Background()

			cert, err := service.Root(ctx)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, cert)
				assert.Contains(t, cert, "BEGIN CERTIFICATE")
				assert.Contains(t, cert, "END CERTIFICATE")

				block, _ := pem.Decode([]byte(cert))
				require.NotNil(t, block)
				assert.Equal(t, "CERTIFICATE", block.Type)

				parsedCert, err := x509.ParseCertificate(block.Bytes)
				require.NoError(t, err)
				assert.True(t, parsedCert.IsCA)
			}
		})
	}
}

func TestService_RootKey(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(fm *files.InMemoryFileManager)
		wantErr bool
	}{
		{
			name:    "root_key_does_not_exist_generates_new",
			setup:   func(_ *files.InMemoryFileManager) {},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm := files.NewInMemoryFileManager()
			tt.setup(fm)

			service := NewService(fm)
			ctx := context.Background()

			key, err := service.RootKey(ctx)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, key)
				assert.Contains(t, key, "BEGIN PRIVATE KEY")
				assert.Contains(t, key, "END PRIVATE KEY")

				block, _ := pem.Decode([]byte(key))
				require.NotNil(t, block)
				assert.Equal(t, "PRIVATE KEY", block.Type)
			}
		})
	}
}

func TestService_Sign(t *testing.T) {
	tests := []struct {
		name    string
		csrPEM  string
		opts    *SignOptions
		wantErr bool
		errType error
	}{
		{
			name:    "valid_csr_no_options",
			csrPEM:  "",
			opts:    nil,
			wantErr: false,
		},
		{
			name:   "valid_csr_with_options",
			csrPEM: "",
			opts: &SignOptions{
				CommonName:         "test.example.com",
				Email:              "test@example.com",
				Organization:       "Test Org",
				Country:            "US",
				State:              "CA",
				Locality:           "San Francisco",
				OrganizationalUnit: "IT",
			},
			wantErr: false,
		},
		{
			name:    "invalid_csr_pem",
			csrPEM:  "invalid pem",
			opts:    nil,
			wantErr: true,
			errType: ErrFailedToParseCSRPEM,
		},
		{
			name:    "malformed_csr",
			csrPEM:  "-----BEGIN CERTIFICATE REQUEST-----\ninvalid\n-----END CERTIFICATE REQUEST-----",
			opts:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm := files.NewInMemoryFileManager()
			service := NewService(fm)
			ctx := context.Background()

			var csrPEM string
			if tt.csrPEM == "" && !tt.wantErr {
				csrPEM = generateTestCSR(t)
			} else {
				csrPEM = tt.csrPEM
			}

			certPEM, err := service.Sign(ctx, csrPEM, tt.opts)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, certPEM)
				assert.Contains(t, certPEM, "BEGIN CERTIFICATE")
				assert.Contains(t, certPEM, "END CERTIFICATE")

				block, _ := pem.Decode([]byte(certPEM))
				require.NotNil(t, block)
				assert.Equal(t, "CERTIFICATE", block.Type)

				parsedCert, err := x509.ParseCertificate(block.Bytes)
				require.NoError(t, err)
				assert.False(t, parsedCert.IsCA)

				if tt.opts != nil {
					validateSignOptions(t, parsedCert, tt.opts)
				}
			}
		})
	}
}

func TestService_Generate(t *testing.T) {
	tests := []struct {
		name            string
		certificatePath string
		keyPath         string
		opts            *SignOptions
		wantErr         bool
	}{
		{
			name:            "generate_with_default_options",
			certificatePath: "test/cert.pem",
			keyPath:         "test/key.pem",
			opts:            nil,
			wantErr:         false,
		},
		{
			name:            "generate_with_custom_options",
			certificatePath: "test/custom_cert.pem",
			keyPath:         "test/custom_key.pem",
			opts: &SignOptions{
				CommonName:         "custom.example.com",
				Email:              "custom@example.com",
				Organization:       "Custom Org",
				Country:            "UK",
				State:              "London",
				Locality:           "Westminster",
				OrganizationalUnit: "Dev",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm := files.NewInMemoryFileManager()
			service := NewService(fm)
			ctx := context.Background()

			certPEM, keyPEM, err := service.Generate(ctx, tt.certificatePath, tt.keyPath, tt.opts)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				assert.NotEmpty(t, certPEM)
				assert.Contains(t, certPEM, "BEGIN CERTIFICATE")
				assert.Contains(t, certPEM, "END CERTIFICATE")

				assert.NotEmpty(t, keyPEM)
				assert.Contains(t, keyPEM, "BEGIN PRIVATE KEY")
				assert.Contains(t, keyPEM, "END PRIVATE KEY")

				certBlock, _ := pem.Decode([]byte(certPEM))
				require.NotNil(t, certBlock)
				parsedCert, err := x509.ParseCertificate(certBlock.Bytes)
				require.NoError(t, err)
				assert.False(t, parsedCert.IsCA)

				keyBlock, _ := pem.Decode([]byte(keyPEM))
				require.NotNil(t, keyBlock)
				_, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
				require.NoError(t, err)

				assert.True(t, fm.Exists(ctx, tt.certificatePath))
				assert.True(t, fm.Exists(ctx, tt.keyPath))

				savedCert, err := fm.Read(ctx, tt.certificatePath)
				require.NoError(t, err)
				assert.Equal(t, certPEM, string(savedCert))

				savedKey, err := fm.Read(ctx, tt.keyPath)
				require.NoError(t, err)
				assert.Equal(t, keyPEM, string(savedKey))
			}
		})
	}
}

func TestService_Fingerprint(t *testing.T) {
	tests := []struct {
		name    string
		certPEM string
		wantErr bool
		errType error
	}{
		{
			name:    "valid_certificate",
			certPEM: "",
			wantErr: false,
		},
		{
			name:    "invalid_pem",
			certPEM: "invalid pem",
			wantErr: true,
			errType: ErrFailedToParseCSRPEM,
		},
		{
			name:    "malformed_certificate",
			certPEM: "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm := files.NewInMemoryFileManager()
			service := NewService(fm)
			ctx := context.Background()

			var certPEM string
			if tt.certPEM == "" && !tt.wantErr {
				cert, _, err := service.Generate(ctx, "test/cert.pem", "test/key.pem", nil)
				require.NoError(t, err)
				certPEM = cert
			} else {
				certPEM = tt.certPEM
			}

			fingerprint, err := service.Fingerprint(certPEM)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, fingerprint)
				assert.Len(t, fingerprint, 64)
				assert.Regexp(t, "^[a-f0-9]{64}$", fingerprint)
			}
		})
	}
}

func TestService_Fingerprint_Consistency(t *testing.T) {
	fm := files.NewInMemoryFileManager()
	service := NewService(fm)
	ctx := context.Background()

	cert, _, err := service.Generate(ctx, "test/cert.pem", "test/key.pem", nil)
	require.NoError(t, err)

	fp1, err := service.Fingerprint(cert)
	require.NoError(t, err)

	fp2, err := service.Fingerprint(cert)
	require.NoError(t, err)

	assert.Equal(t, fp1, fp2)
}

func TestService_RootGeneration_Persistence(t *testing.T) {
	fm := files.NewInMemoryFileManager()
	service := NewService(fm)
	ctx := context.Background()

	cert1, err := service.Root(ctx)
	require.NoError(t, err)

	key1, err := service.RootKey(ctx)
	require.NoError(t, err)

	cert2, err := service.Root(ctx)
	require.NoError(t, err)

	key2, err := service.RootKey(ctx)
	require.NoError(t, err)

	assert.Equal(t, cert1, cert2)
	assert.Equal(t, key1, key2)
}

func validateSignOptions(t *testing.T, cert *x509.Certificate, opts *SignOptions) {
	t.Helper()

	if opts.CommonName != "" {
		assert.Equal(t, opts.CommonName, cert.Subject.CommonName)
	}
	if opts.Organization != "" {
		require.Len(t, cert.Subject.Organization, 1)
		assert.Equal(t, opts.Organization, cert.Subject.Organization[0])
	}
	if opts.Country != "" {
		require.Len(t, cert.Subject.Country, 1)
		assert.Equal(t, opts.Country, cert.Subject.Country[0])
	}
	if opts.State != "" {
		require.Len(t, cert.Subject.Province, 1)
		assert.Equal(t, opts.State, cert.Subject.Province[0])
	}
	if opts.Locality != "" {
		require.Len(t, cert.Subject.Locality, 1)
		assert.Equal(t, opts.Locality, cert.Subject.Locality[0])
	}
	if opts.OrganizationalUnit != "" {
		require.Len(t, cert.Subject.OrganizationalUnit, 1)
		assert.Equal(t, opts.OrganizationalUnit, cert.Subject.OrganizationalUnit[0])
	}
}

func generateTestCSR(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test"},
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	require.NoError(t, err)

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return string(csrPEM)
}
