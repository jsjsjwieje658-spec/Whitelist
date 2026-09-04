all: clean build entitlements package clean

PROJECT = $(shell basename *.xcodeproj)
WORKING_LOCATION := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
TARGET = Whitelist
CONFIGURATION = Release
SDK = iphoneos
APP_PATH = DerivedData/Build/Products/$(CONFIGURATION)-$(SDK)/$(TARGET).app

build:
	echo "Building $(TARGET) for $(SDK)..."
	xcodebuild -project $(PROJECT) \
		-scheme $(TARGET) \
		-configuration $(CONFIGURATION) \
		-sdk $(SDK) \
		-derivedDataPath DerivedData \
		CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO \
		ASSETCATALOG_COMPILER_GENERATE_SWIFT_ASSET_SYMBOL_EXTENSIONS=NO \
		ENABLE_PREVIEWS=NO DEVELOPMENT_ASSET_PATHS="" build
	echo "Build finished!"

entitlements:
	echo "Adding entitlements..."
	chmod a+x $(WORKING_LOCATION)bin/ldid
	$(WORKING_LOCATION)bin/ldid -S"$(WORKING_LOCATION)entitlements.plist" "$(APP_PATH)"
	echo "Entitlements added!"

package:
	echo "Packaging app..."
	rm -rf Payload
	mkdir Payload
	cp -r $(APP_PATH) Payload
	zip -r $(TARGET).ipa Payload
	echo "Packaging finished!"

clean:
	rm -rf Payload
	rm -rf DerivedData
	echo "All done!"
