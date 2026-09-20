SITE := site
DEST := haig:/diagspill/
SSH_IDENTITY := $(HOME)/.ssh/id-kimmo-cloud-htdocs

BANNER_SVG := $(SITE)/assets/diagspill-tracker.svg
BANNER_PNG := $(SITE)/static/diagspill-tracker.png

.PHONY: build dist banner check

# Rasterise the social-media / OpenGraph banner from its SVG source.
# The PNG is committed, so this — and the resvg + banner-fonts
# (Roboto, Liberation Mono) dependency — is only needed after
# editing the SVG.
banner:
	resvg $(BANNER_SVG) $(BANNER_PNG)

build:
	cd $(SITE) && hugo --minify --gc --cleanDestinationDir

dist: build
	rsync -avz --delete --chmod=Da+rx,Fa+r -e 'ssh -i $(SSH_IDENTITY) -o IdentitiesOnly=yes' $(SITE)/public/ $(DEST)

# Run the helper-script tests under scripts/.
check:
	python3 -m unittest discover -s tests
