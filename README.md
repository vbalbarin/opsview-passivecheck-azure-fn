# Opsview Passive Check Relay Function

## Overview

blah, blah, blah

## Running

```bash
cp config.yaml.template config.yaml

# Make appropriate changes to default values in config.yaml
# or set them via environment variables passed to container.


```

```bash
# set the python version to the one requred by current MS image
export AZURE_FUNCTION_PYTHON_VERSION=3.6.6

pyenv install ${AZURE_FUNCTION_PYTHON_VERSION}

```


```bash
## set the python version to the one required by current MS image
export AZURE_FUNCTION_PYTHON_VERSION=3.6.6
export AZURE_FUNCTION_NAME=opsview-passivecheck-fn


mkdir ${AZURE_FUNCTION_NAME}
echo $(AZURE_FUNCTION_PYTHON_VERSION} > ${AZURE_FUNCTION_NAME}/.python-version
cd ${AZURE_FUNCTION_NAME}

## create virtualenv for Azure Function
pyenv virtualenv ${AZURE_FUNCTION_PYTHON_VERSION} ${AZURE_FUNCTION_NAME}
pyenv activate ${AZURE_FUNCTION_NAME}

## initialize Azure function directory
func init --worker-runtime python --docker

## create new function with docker option
func new --name 'HttpTrigger' --template HttpTrigger --language python

## build Docker container for function
## `cat`ting VERSION links docker tag version to VERSION embedded in source
docker build . --tag localhost/${AZURE_FUNCTION_NAME}:$(cat VERSION)

## run container
docker run -p 8080:80 -it localhost/${AZURE_FUNCTION_NAME}:$(cat VERSION)

## in separate shell or browser
## curl http://localhost:8080/api/HttpTrigger/?name=foo
## should return `Hello foo!`

## Ctrl-C in original shell
## Alternatively `docker -aq | xargs docker stop` in shell used to test to stop the container

## tag with latest
docker tag localhost/${AZURE_FUNCTION_NAME}:$(cat VERSION) localhost/${AZURE_FUNCTION_NAME}:latest



```


## Notes
```bash
# Push to Azure Container Registry
# Login to Azure Container Registry

export AZURE_CONTAINER_REGISTRY=ftscontainers
export AZURE_SUBSCRIPTION_NAME='Azure ITS Sandbox'

az login
az account set --subscription ${AZURE_SUBSCRIPTION_NAME}

az acr login --name ${AZURE_CONTAINER_REGISTRY}

export AZURE_CONTAINER_REPOSITORY=$(az acr )
```