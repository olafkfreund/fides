package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/olafkfreund/terraform-provider-fides/internal/provider"
)

func main() {
	if err := providerserver.Serve(context.Background(), provider.New, providerserver.ServeOpts{
		Address: "registry.terraform.io/olafkfreund/fides",
	}); err != nil {
		log.Fatal(err)
	}
}
