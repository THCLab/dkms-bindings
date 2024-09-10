BIN = ./node_modules/.bin
.PHONY: release-patch release-minor publish

define release
    VERSION=`node -pe "require('./package.json').version"` && \
    NEXT_VERSION=`node -pe "require('semver').inc(\"$$VERSION\", '$(1)')"` && \
    node -e "\
        var j = require('./package.json');\
        j.version = \"$$NEXT_VERSION\";\
        var s = JSON.stringify(j, null, 2);\
        require('fs').writeFileSync('./package.json', s);" && \
    npm i && \
		git add package.json package-lock.json && git commit -m "chore: Version $$NEXT_VERSION" && \
    git tag "node.js-$$NEXT_VERSION" -m "Version $$NEXT_VERSION"
endef

release-patch:
	@$(call release,patch)

release-minor:
	@$(call release,minor)

release-major:
	@$(call release,major)

publish:
	git push --tags
	git push origin master
