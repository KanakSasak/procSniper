//go:build gui && windows

package main

import (
	"embed"
	"io/fs"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	"procSniper/internal/delivery/gui"
)

// Embed the frontend dist folder
// Run 'npm run build' in frontend/ directory to generate this
//go:embed all:cmd/gui/dist
var assets embed.FS

func main() {
	// Create application instance
	app := gui.NewApp()

	// Get the subdirectory as the root for serving
	distFS, err := fs.Sub(assets, "cmd/gui/dist")
	if err != nil {
		log.Fatal("Failed to get embedded assets:", err)
	}

	// Create Wails application
	err = wails.Run(&options.App{
		Title:     "procSniper - Ransomware Protection",
		Width:     1280,
		Height:    800,
		MinWidth:  1024,
		MinHeight: 600,
		AssetServer: &assetserver.Options{
			Assets: distFS,
		},
		BackgroundColour: &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		OnStartup:        app.Startup,
		OnShutdown:       app.Shutdown,
		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewIsTransparent:              false,
			WindowIsTranslucent:               false,
			DisableWindowIcon:                 false,
			DisableFramelessWindowDecorations: false,
			WebviewUserDataPath:               "",
			WebviewBrowserPath:                "",
			Theme:                             windows.SystemDefault,
		},
	})

	if err != nil {
		log.Fatal("Error starting application:", err)
	}
}
