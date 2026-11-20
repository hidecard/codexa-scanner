package main

import (
	"embed"
	"log"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	if len(os.Args) > 1 {
		os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
	}
	log.Println("Codexa Scanner: main() starting...")
	app := NewApp()
	log.Println("Codexa Scanner: app created, starting wails...")
	err := wails.Run(&options.App{
		Title:       "Codexa Scanner",
		Width:       1200,
		Height:      800,
		MinWidth:    900,
		MinHeight:   650,
		AssetServer: &assetserver.Options{Assets: assets},
		OnStartup:   app.startup,
		OnShutdown:  app.shutdown,
		Bind:        []interface{}{app},
	})
	if err != nil {
		log.Fatal(err)
	}
}
