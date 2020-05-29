/*******************************************************************************
 * Copyright 2020 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/

package main

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/project-alvarium/go-store/pkg/http/client"
	"github.com/project-alvarium/go-store/pkg/http/requestor"

	"github.com/project-alvarium/go-sdk/pkg/annotation"
	metadataFactory "github.com/project-alvarium/go-sdk/pkg/annotation/metadata/factory"
	"github.com/project-alvarium/go-sdk/pkg/annotation/uniqueprovider/ulid"
	"github.com/project-alvarium/go-sdk/pkg/annotator"
	"github.com/project-alvarium/go-sdk/pkg/annotator/assess"
	pkiAssessor "github.com/project-alvarium/go-sdk/pkg/annotator/assess/assessor/pki"
	"github.com/project-alvarium/go-sdk/pkg/annotator/assess/assessor/pki/factory/verifier"
	assessMetadataFactory "github.com/project-alvarium/go-sdk/pkg/annotator/assess/metadata/factory"
	filterFactory "github.com/project-alvarium/go-sdk/pkg/annotator/filter/matching"
	"github.com/project-alvarium/go-sdk/pkg/annotator/filter/passthrough"
	pkiAnnotator "github.com/project-alvarium/go-sdk/pkg/annotator/pki"
	pkiMetadataFactory "github.com/project-alvarium/go-sdk/pkg/annotator/pki/metadata/factory"
	"github.com/project-alvarium/go-sdk/pkg/annotator/pki/signer/signpkcs1v15"
	"github.com/project-alvarium/go-sdk/pkg/annotator/pki/signer/signtpmv2"
	"github.com/project-alvarium/go-sdk/pkg/annotator/pki/signer/signtpmv2/factory"
	"github.com/project-alvarium/go-sdk/pkg/annotator/pki/signer/signtpmv2/provisioner"
	"github.com/project-alvarium/go-sdk/pkg/annotator/provenance"
	"github.com/project-alvarium/go-sdk/pkg/annotator/publish"
	publishMetadata "github.com/project-alvarium/go-sdk/pkg/annotator/publish/metadata"
	publishMetadataFactory "github.com/project-alvarium/go-sdk/pkg/annotator/publish/metadata/factory"
	"github.com/project-alvarium/go-sdk/pkg/annotator/publish/publisher/example"
	"github.com/project-alvarium/go-sdk/pkg/annotator/publish/publisher/example/writer/testwriter"
	"github.com/project-alvarium/go-sdk/pkg/annotator/publish/publisher/iota"
	"github.com/project-alvarium/go-sdk/pkg/annotator/publish/publisher/ipfs"
	ipfsPublisherMetadata "github.com/project-alvarium/go-sdk/pkg/annotator/publish/publisher/ipfs/metadata"
	"github.com/project-alvarium/go-sdk/pkg/hashprovider/sha256"
	identityFactory "github.com/project-alvarium/go-sdk/pkg/identity/factory"
	identityProvider "github.com/project-alvarium/go-sdk/pkg/identityprovider/hash"
	"github.com/project-alvarium/go-sdk/pkg/sdk"
	"github.com/project-alvarium/go-sdk/pkg/test"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/iotaledger/iota.go/api"
)

var privateKey = fmt.Sprintf("%s",
	"-----BEGIN RSA PRIVATE KEY-----\n"+
		"MIIEpQIBAAKCAQEA+Cl+aPrXYrmBLPj7MflVSnC0Cnb+08C8+UyQx/llWbdzbsOp\n"+
		"pUix2gvMeUIeqbrDggu1ac8ogwjRuRdiAL0sygCutCMD4jB/2d0x2FEgvKbRdufD\n"+
		"2tbOQ2PniqoJr9IbYHMJYWAKDKWrCXcV+g5Jk/hKSCtmDrgvGN3gmbargtWmFGLb\n"+
		"IGcJ9HqfAeLc4tuCZ91i/I1cvKUaqfdAJkJeEbrHw0PuGDywpqfPlDCclJX+cOOP\n"+
		"W4jCGWd4Db42vlSjCBfq4Z0MBX++u4P8uyx6SC2LrlEdRO43yB/ryBR17IioCSxu\n"+
		"khavfZHbYPEwrLTYarx8FY62FUgcffzcsmhxZwIDAQABAoIBAQCtw1gpJ+Mi1KOX\n"+
		"mutAzcYj7pCSd0nteZqYsTz7WSzXSjYAi+7Atgsak4JkMaEI1aZJ6+rmINDMF6PK\n"+
		"B45u2AeBlkK+DXqNqcoMAe8B+aSDlAc9TAF+vUQGOfEJzhAkVWkn+sTJsxa2TlZZ\n"+
		"tVHlGpX4jzVsHT9D9UG9FrdKynaDj7bMf+sJHiuo9cAAIauZ3BTIAR81Zu+SgfYI\n"+
		"95MqW9qrvBVW0zIlqkNeYXbM6dCGZlVm2BS2EdcfwFvhbKjXFqUUm8FOn4VQtcSs\n"+
		"5/F4oDSncb6uT4hyC2335A7EvEKcfkaSb1AbpDUMIhjvlWfYeyXlQvYUIpKCzE21\n"+
		"WnkILCCJAoGBAP+nnPDMq9nklp3ZBWMzF4wvdZD3nxep4oFg7fwIPKNnEHpI3/zI\n"+
		"fDQsjnMpvzP/ZOzmMXr0sE+XwiDJ4nCCRTm0+yCD3P1VZ4KKbp6MaWa5pRCCk9QK\n"+
		"FpnzZu4C1l4JgG+HJilxN/jSfijRsxLcmbRm2fEFbjeQdV3sj9UHNHo1AoGBAPh/\n"+
		"SlKCOnSUJGCLZzbj3dUG1uso0UzE9mY8NoZxS5L1vSh98OejjXJb9VmAafsZmjdx\n"+
		"PMd/sggLkgeQTkIu4AUEwsX9i/9bOzjyXr3+SPxF+BIc5LH4zuFXoyiCiFUaYmfB\n"+
		"XvwXs9OO7/F//oRiFVY1uFavKnWvi7gr1k8CyZCrAoGBAJaDX+qFFUgbRHF6K6nT\n"+
		"krF934GRx6Bu7GOvZW1UjB7HtvPHo9d3UWiGMveqRF+gpRK0E72IAaVae3hCY4ZJ\n"+
		"q+flnVPvTlP3zBEW3zmJASTxdzTZK59SsSvCGX9XPE3w2iTPNLCBb6qWgqAVlZAt\n"+
		"QHDtfLJhuBoOeorpk2Sf8U1hAoGBAO5MKvqqleH7ulK2/DjAFZfWoj0KfIPREbUC\n"+
		"owsUFHQOoeH1vBJ2Xgs/si2tHnTEnYXzWmS5yQE8D0KfmNyQ1RUa9qklNp6fX1CB\n"+
		"5GbwNg9uDbFY8drVjZa9EuKjIpfx4FI9NpgrJrCHDwQZSPqskGeGxoqiGeaXfDYW\n"+
		"G8LTGnZXAoGAScksu0S+ScRp+++9KvlyTLD9uMw3Soceb/iqA63ZZI814tlQO10K\n"+
		"/0kXqd4O+fR5Ef7+J6f68RQ8ND4XmJJy8lcE4vkc1DS3PYznyLB/2tPZzeNxYOCE\n"+
		"8Pi5JgSArgEYUwWJtob3rTsUoBjnEB76AtgIXCDBjo/GWorhvTyPMJw=\n"+
		"-----END RSA PRIVATE KEY-----\n",
)

var ValidPrivateKey = []byte(privateKey)

var publicKey = fmt.Sprintf("%s",
	"-----BEGIN PUBLIC KEY-----\n"+
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+Cl+aPrXYrmBLPj7MflV\n"+
		"SnC0Cnb+08C8+UyQx/llWbdzbsOppUix2gvMeUIeqbrDggu1ac8ogwjRuRdiAL0s\n"+
		"ygCutCMD4jB/2d0x2FEgvKbRdufD2tbOQ2PniqoJr9IbYHMJYWAKDKWrCXcV+g5J\n"+
		"k/hKSCtmDrgvGN3gmbargtWmFGLbIGcJ9HqfAeLc4tuCZ91i/I1cvKUaqfdAJkJe\n"+
		"EbrHw0PuGDywpqfPlDCclJX+cOOPW4jCGWd4Db42vlSjCBfq4Z0MBX++u4P8uyx6\n"+
		"SC2LrlEdRO43yB/ryBR17IioCSxukhavfZHbYPEwrLTYarx8FY62FUgcffzcsmhx\n"+
		"ZwIDAQAB\n"+
		"-----END PUBLIC KEY-----\n",
)

var ValidPublicKey = []byte(publicKey)

const (
	// IOTA constants
	iotaURL              = "http://localhost:14265"
	iotaDepth     uint64 = 3
	iotaMWM       uint64 = 9
	trytesCharset        = "ABCDEFGHIJKLMNOPQRSTUVWXYZ9"
	seedSize             = 81

	// IPFS constants
	ipfsURL = "localhost:5001"
)

// factoryRandomSeedString returns an IOTA Tangle seed with a random value.
func factoryRandomSeedString() string {
	return test.FactoryRandomFixedLengthString(seedSize, trytesCharset)
}

// exampleData defines the structure of the example data.
type exampleData struct {
	Name  string
	Value int
}

// tpmSetUp creates a temporary key and certificate to use for the example.
func tpmSetUp(path string) (io.ReadWriteCloser, tpmutil.Handle, string, []byte, func()) {
	rwc, err := factory.TPM(path)
	if err != nil {
		fmt.Println("Unable to factory TPM instance")
		os.Exit(1)
	}

	handle, publicKey, err := provisioner.GenerateNewKeyPair(rwc)
	if err != nil {
		fmt.Println("Unable to generate new key pair")
		os.Exit(1)
	}

	return rwc,
		handle,
		path,
		provisioner.MarshalPublicKey(publicKey),
		func() {
			provisioner.Flush(rwc, handle)
		}
}

// newExampleData is a factory function that returns an initialized exampleData.
func newExampleData() *exampleData {
	return &exampleData{
		Name:  test.FactoryRandomString(),
		Value: test.FactoryRandomInt(),
	}
}

// newProvenance is a factory function that returns a provenance.Contract.
func newProvenance(node string) provenance.Contract {
	return &struct {
		Node string `json:"node"`
	}{
		Node: node,
	}
}

// newClient is a factory function that returns an api.API reference.
func newClient(url string) *api.API {
	c, err := api.ComposeAPI(api.HTTPClientSettings{URI: url})
	if err != nil {
		fmt.Println("Unable to factory IOTA API instance")
		os.Exit(1)
	}
	return c
}

// main is the example entry point.
func main() {
	mFactory := metadataFactory.New(
		[]metadataFactory.Contract{
			assessMetadataFactory.NewDefault(),
			pkiMetadataFactory.NewDefault(),
			publishMetadataFactory.NewDefault(),
		},
	)
	iFactory := identityFactory.New()
	hashProvider := sha256.New()
	uniqueProvider := ulid.New()
	idProvider := identityProvider.New(hashProvider)
	persistence := client.New(requestor.New("http://localhost:8081").Handler, mFactory, iFactory)
	passthroughFilter := passthrough.New()

	// create new TPM keys
	rwc, tpmHandle, tpmPath, publicKey, cleanUp := tpmSetUp(provisioner.Path)

	// create SDK instance for annotation and assessment.
	p := newProvenance("origin")
	sdkInstance := sdk.New(
		[]annotator.Contract{
			pkiAnnotator.New(
				p,
				uniqueProvider,
				idProvider,
				persistence,
				signtpmv2.NewWithRWC(
					hashProvider,
					publicKey,
					tpmHandle,
					tpmPath,
					signtpmv2.RequestedCapabilityProperties{
						"Version":      tpm2.FamilyIndicator,
						"Manufacturer": tpm2.Manufacturer,
					},
					rwc),
			),
			assess.New(
				p,
				uniqueProvider,
				idProvider,
				persistence,
				pkiAssessor.New(verifier.New()),
				passthroughFilter,
			),
		},
	)

	// register data creation.
	data := newExampleData()
	dataAsBytes, _ := json.Marshal(data)
	_ = sdkInstance.Create(dataAsBytes)

	// cleanup TPM resources and close SDK instance.
	cleanUp()
	sdkInstance.Close()

	// create SDK instance for annotation and assessment.
	p = newProvenance("transit-1")
	sdkInstance = sdk.New(
		[]annotator.Contract{
			pkiAnnotator.New(
				p,
				uniqueProvider,
				idProvider,
				persistence,
				signpkcs1v15.New(crypto.SHA256, ValidPrivateKey, ValidPublicKey, hashProvider),
			),
			assess.New(
				p,
				uniqueProvider,
				idProvider,
				persistence,
				pkiAssessor.New(verifier.New()),
				passthroughFilter,
			),
		},
	)

	// modify data; register data mutation.
	data.Value += 1
	newDataAsBytes, _ := json.Marshal(data)
	_ = sdkInstance.Mutate(dataAsBytes, newDataAsBytes)

	// close SDK instance.
	sdkInstance.Close()

	// create SDK instance for annotation and assessment.
	p = newProvenance("transit-2")
	sdkInstance = sdk.New(
		[]annotator.Contract{
			pkiAnnotator.New(
				p,
				uniqueProvider,
				idProvider,
				persistence,
				signpkcs1v15.New(crypto.SHA256, ValidPrivateKey, ValidPublicKey, hashProvider),
			),
			assess.New(
				p,
				uniqueProvider,
				idProvider,
				persistence,
				pkiAssessor.New(verifier.New()),
				passthroughFilter,
			),
		},
	)

	// even though no mutation occurred, register data mutation to capture transit event.
	_ = sdkInstance.Mutate(newDataAsBytes, newDataAsBytes)

	// close SDK instance.
	sdkInstance.Close()

	// create SDK instance for publishing.
	p = newProvenance("publisher")
	w := testwriter.New()
	sdkInstance = sdk.New(
		[]annotator.Contract{
			publish.New(p, uniqueProvider, idProvider, persistence, ipfs.New(ipfsURL), passthroughFilter),
			publish.New(
				p,
				uniqueProvider,
				idProvider,
				persistence,
				iota.New(factoryRandomSeedString(), iotaDepth, iotaMWM, newClient(iotaURL)),
				filterFactory.New(
					func(annotation *annotation.Instance) bool {
						t, ok := annotation.Metadata.(*publishMetadata.Instance)
						return ok && t.PublisherKind == ipfsPublisherMetadata.Kind
					},
				),
			),
			publish.New(p, uniqueProvider, idProvider, persistence, example.New(w), passthroughFilter),
		},
	)

	// publish result.
	_ = sdkInstance.Create(newDataAsBytes)

	// display it.
	fmt.Printf("%s\n", w.Get())

	// close SDK instance
	sdkInstance.Close()
}
