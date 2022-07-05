build:
	mvn clean package install

build-tokenmapper:
	mvn clean install -pl tokenmapper -am

build-required-action:
	mvn clean install -pl required-action -am
