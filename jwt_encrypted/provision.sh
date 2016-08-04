#!/bin/bash
# -*- mode:shell-script; coding:utf-8; -*-
#
# Provisioning helper script for the jwt_encrypted API. 

# This script does these things: undeploys older versions of the API
# Proxy, removes old developer accounts, apps, and products.  Then,
# deploys a new version of the proxy, creates a product for that proxy,
# creates a developer, and a developer app with authorization on the
# product. It also inserts the public key as a custom attribute onto the
# developer app.  Finally, it creates or verifies that a vault exists,
# and finally inserts a private key and a password into the vault.
#
# The result is that the jwt_encrypted API is callable with a regular
# curl command.
# 
# 
# Created: <Thu Nov  5 13:30:29 2015>
# Last Updated: <2016-July-28 08:44:43>
#

apiname=jwt_encrypted
vaultname=privateKeysByApp
privkeypasswd=""
privkeyfile=""
pubkeyfile=""
defaultpubkeyfile=keys/key1-public.pem
defaultprivkeyfile=keys/key1-private-encrypted.pem
defaultmgmtserver="https://api.enterprise.apigee.com"
mgmtserver=""
org=""
env=""
credentials=""
netrccreds=0

vaultexists=0
quotalimit=1000
resetonly=0
have_deployments=0
verbosity=2


function usage() {
  local CMD=`basename $0`
  echo "$CMD: "
  echo "  Provisions an API Proxy, an API product, a developer, and a developer app, as"
  echo "  well as vault entries for the jwt_encrypted API Proxy. "
  echo "  Uses the curl utility."
  echo "usage: "
  echo "  $CMD [options] "
  echo "options: "
  echo "  -m url    the base url for the mgmt server."
  echo "  -o org    the org to use."
  echo "  -e env    the environment to deploy to."
  echo "  -u creds  http basic authn credentials for the API calls."
  echo "  -n        tells curl to use .netrc to retrieve credentials"
  echo "  -f        private key file. Should be pem encoded."
  echo "  -p        private key file password.."
  echo "  -b        public key file. Should be pem encoded."
  echo "  -r        reset state only. Removes products and developers and apps."
  echo
  echo "Current parameter values:"
  echo "  mgmt api url: $defaultmgmtserver"
  echo "   environment: $env"
  echo
  exit 1
}

function random_string() {
  local rand_string
  rand_string=$(cat /dev/urandom |  LC_CTYPE=C  tr -cd '[:alnum:]' | head -c 10)
  echo ${rand_string}
}

## function MYCURL
## Print the curl command, omitting sensitive parameters, then run it.
## There are side effects:
## 1. puts curl output into file named ${CURL_OUT}. If the CURL_OUT
##    env var is not set prior to calling this function, it is created
##    and the name of a tmp file in /tmp is placed there.
## 2. puts curl http_status into variable CURL_RC
function MYCURL() {
  [ -z "${CURL_OUT}" ] && CURL_OUT=`mktemp /tmp/apigee-iloveapis2015-provision.curl.out.XXXXXX`
  [ -f "${CURL_OUT}" ] && rm ${CURL_OUT}
  [ $verbosity -gt 0 ] && echo "curl $@"

  # run the curl command
  CURL_RC=`curl $credentials -s -w "%{http_code}" -o "${CURL_OUT}" "$@"`
  [ $verbosity -gt 0 ] && echo "==> ${CURL_RC}"
}

function parse_deployments_output() {
  ## extract the environment names and revision numbers in the list of deployments.
  output_parsed=`cat ${CURL_OUT} | grep -A 6 -B 2 "revision"`

  if [ $? -eq 0 ]; then

    deployed_envs=`echo "${output_parsed}" | grep -B 2 revision | grep name | sed -E 's/[\",]//g'| sed -E 's/name ://g'`

    deployed_revs=`echo "${output_parsed}" | grep -A 5 revision | grep name | sed -E 's/[\",]//g'| sed -E 's/name ://g'`

    IFS=' '; declare -a rev_array=(${deployed_revs})
    IFS=' '; declare -a env_array=(${deployed_envs})

    m=${#rev_array[@]}
    if [ $verbosity -gt 1 ]; then
      echo "found ${m} deployed revisions"
    fi

    deployments=()
    let m-=1
    while [ $m -ge 0 ]; do
      rev=${rev_array[m]}
      env=${env_array[m]}
      # trim spaces
      rev="$(echo "${rev}" | tr -d '[[:space:]]')"
      env="$(echo "${env}" | tr -d '[[:space:]]')"
      echo "${env}=${rev}"
      deployments+=("${env}=${rev}")
      let m-=1
    done
    have_deployments=1
  fi
}


## function clear_env_state
## Removes any developer app with the prefix of ${apiname}, and any
## developer or api product with that prefix, and any API with that
## name.
function clear_env_state() {
  local prodarray devarray apparray revisionarray prod env rev deployment dev app i j

  echo "  check for developers like ${apiname}..."
  MYCURL -X GET ${mgmtserver}/v1/o/${org}/developers
  if [ ${CURL_RC} -ne 200 ]; then
    echo 
    echo "Cannot retrieve developers from that organization..."
    exit 1
  fi
  devarray=(`cat ${CURL_OUT} | grep "\[" | sed -E 's/[]",[]//g'`)
  for i in "${!devarray[@]}"; do
    dev=${devarray[i]}
    if [[ "$dev" =~ ^${apiname}.+$ ]] ; then
      echo "  found a matching developer..."
      echo "  list the apps for that developer..."
      MYCURL -X GET "${mgmtserver}/v1/o/${org}/developers/${dev}/apps"
      apparray=(`cat ${CURL_OUT} | grep "\[" | sed -E 's/[]",[]//g'`)
      for j in "${!apparray[@]}"
      do
        app=${apparray[j]}
        echo "  delete the app ${app}..."
        MYCURL -X DELETE "${mgmtserver}/v1/o/${org}/developers/${dev}/apps/${app}"
        ## ignore errors
      done       

      echo "  delete the developer $dev..."
      MYCURL -X DELETE "${mgmtserver}/v1/o/${org}/developers/${dev}"
      if [ ${CURL_RC} -ne 200 ]; then
        echo 
        echo "  could not delete that developer (${dev})"
        echo 
        exit 1
      fi
    fi
  done

  echo "  check for api products like ${apiname}..."
  MYCURL -X GET ${mgmtserver}/v1/o/${org}/apiproducts
  if [ ${CURL_RC} -ne 200 ]; then
    echo 
    echo "Cannot retrieve apiproducts from that org..."
    exit 1
  fi

  prodarray=(`cat ${CURL_OUT} | grep "\[" | sed -E 's/[]",[]//g'`)
  for i in "${!prodarray[@]}"; do
    prod=${prodarray[i]}

    if [[ "$prod" =~ ^${apiname}.+$ ]] ; then
       echo "  found a matching product...deleting it."
       MYCURL -X DELETE ${mgmtserver}/v1/o/${org}/apiproducts/${prod}
       if [ ${CURL_RC} -ne 200 ]; then
         echo 
         echo "  could not delete that product (${prod})"
         echo 
         exit 1
       fi
    fi
  done

  echo "  check for the ${apiname} apiproxy..."
  MYCURL -X GET "${mgmtserver}/v1/o/${org}/apis/${apiname}/deployments"
  if [ ${CURL_RC} -eq 200 ]; then
    echo "  found, querying it..."
    parse_deployments_output

    # undeploy from any environments in which the proxy is deployed
    for deployment in ${deployments[@]}; do
      env=`expr "${deployment}" : '\([^=]*\)'`
      # trim spaces
      env="$(echo "${env}" | tr -d '[[:space:]]')"
      rev=`expr "$deployment" : '[^=]*=\([^=]*\)'`
      MYCURL -X POST "${mgmtserver}/v1/o/${org}/apis/${apiname}/revisions/${rev}/deployments?action=undeploy&env=${env}"
      ## ignore errors
    done

    # delete all revisions
    MYCURL -X GET ${mgmtserver}/v1/o/${org}/apis/${apiname}/revisions
    revisionarray=(`cat ${CURL_OUT} | grep "\[" | sed -E 's/[]",[]//g'`)
    for i in "${!revisionarray[@]}"; do
      rev=${revisionarray[i]}
      echo "  delete revision $rev"
      MYCURL -X DELETE "${mgmtserver}/v1/o/${org}/apis/${apiname}/revisions/${rev}"
    done

    if [ $resetonly -eq 1 ] ; then
        echo "  delete the api"
        MYCURL -X DELETE ${mgmtserver}/v1/o/${org}/apis/${apiname}
        if [ ${CURL_RC} -ne 200 ]; then
          echo "failed to delete that API"
        fi 
    fi 
  fi
}


function get_privatekey() {
  local value password
  if [ "X$privkeyfile" = "X" ]; then
    read -p "private key file (${defaultprivkeyfile}) :: " value
    value="${value:-$defaultprivkeyfile}"
    privkeyfile=$value
    #echo "privkeyfile: $privkeyfile"
  fi

  if [ ! -f "$privkeyfile" ]; then
    echo "$privkeyfile is missing"
    echo
    exit 1
  fi

  # replace newlines with pipe characters before
  # inserting the private key into the vault. 
  #
  # This will need to be reversed at runtime when the key is retrieved. 
  privateKey=`sed -e 'H;1h;$!d;x;y/\n/|/' $privkeyfile`

  echo "private key:"
  echo $privateKey
  if [ -z "$privateKey" ]; then
    echo "$privkeyfile is empty?"
    echo
    exit 1
  fi
  
  if [ "X$privkeypasswd" = "X" ]; then
    echo -n "Private key password: "
    read -s password
    echo
    privkeypasswd="${password}"
  fi
}

function get_publickey() {
  local value 
  if [ "X$pubkeyfile" = "X" ]; then
    read -p "public key file (${defaultpubkeyfile}) :: " value
    value="${value:-$defaultpubkeyfile}"
    pubkeyfile=$value
  fi

  if [ ! -f "$pubkeyfile" ]; then
    echo "$pubkeyfile is missing"
    echo
    exit 1
  fi

  # replace newlines with pipe characters before
  # inserting the public key into the custom attribute.
  #
  # This will need to be reversed at runtime when the key is retrieved. 
  publicKey=`sed -e 'H;1h;$!d;x;y/\n/|/' $pubkeyfile`
  echo "public key:"
  echo $publicKey
  if [ -z "$publicKey" ]; then
    echo "$publicKey is empty?"
    echo
    exit 1
  fi
}

function delete_vault_entry_ifexists() {
  local entry=$1
  echo 
  echo inquire the vault entry
  MYCURL -X GET $mgmtserver/v1/o/$org/e/$env/vaults/${vaultname}/entries/$entry 
  if [ ${CURL_RC} -eq 200 ]; then
    echo 
    echo delete the existing entry
    MYCURL -X DELETE $mgmtserver/v1/o/$org/e/$env/vaults/${vaultname}/entries/$entry 
    if [ ${CURL_RC} -ne 200 ]; then
      echo failed.
      cat ${CURL_OUT} 
      echo
      exit
    fi
  fi
}

function insert_vault_entry() {
  local payload
  #   -d '{ "name": "'$apiKey'", "value": "'$privateKey'" }' 
  payload=$'{ "name": "'
  payload+=$1
  payload+=$'", "value": "'
  payload+=$2
  payload+=$'" }' 

  MYCURL -X POST \
    -H content-type:application/json \
    $mgmtserver/v1/o/$org/e/$env/vaults/${vaultname}/entries \
    --data-binary "$payload"
  echo

  if [ ${CURL_RC} -ne 201 ]; then
    echo failed.
    cat ${CURL_OUT} 
    echo
    exit
  fi
}


function choose_credentials() {
  local username password
  read -p "orgadmin username for org ${org} at ${mgmtserver} ? (blank to use .netrc): " username
  echo
  if [[ "$username" = "" ]] ; then  
    credentials="-n"
  else
    echo -n "Org Admin Password: "
    read -s password
    echo
    credentials="-u ${username}:${password}"
  fi
}

function check_org() {
  echo "checking organization ${org}..."
  MYCURL -X GET  ${mgmtserver}/v1/o/${org}
  if [ ${CURL_RC} -eq 200 ]; then
    check_org=0
  else
    check_org=1
  fi
}

function check_env() {
  echo "checking environment ${env}..."
  MYCURL -X GET  ${mgmtserver}/v1/o/${org}/e/${env}
  if [ ${CURL_RC} -eq 200 ]; then
    check_env=0
  else
    check_env=1
  fi
}

function choose_org() {
  local all_done
  all_done=0
  while [ $all_done -ne 1 ]; do
      echo
      read -p "  Which organization? " org
      check_org 
      if [ ${check_org} -ne 0 ]; then
        echo cannot read that organization with the given creds.
        echo
        all_done=0
      else
        all_done=1
      fi
  done
  echo
  echo "  org = ${org}"
}

function choose_env() {
  local all_done
  all_done=0
  while [ $all_done -ne 1 ]; do
      echo
      read -p "  Which environment? " env
      check_env
      if [ ${check_env} -ne 0 ]; then
        echo cannot read that env with the given creds.
        echo
        all_done=0
      else
        all_done=1
      fi
  done
  echo
  echo "  env = ${env}"
}

function deploy_new_bundle() {
  if [ ! -d "apiproxy" ] ; then 
     echo cannot find the apiproxy directory.
     echo re-run this command from the appropriate directory. 
     echo
     exit 1
  fi

  if [ -f "$apiname.zip" ]; then
    if [ $verbosity -gt 0 ]; then
      echo "removing the existing zip..."
    fi
    rm -f "$apiname.zip"
  fi

  echo "  produce the bundle..."
  zip -r "${apiname}.zip" apiproxy  -x "*/*.*~" -x "*/Icon*" -x "*/#*.*#" -x "*/node_modules/*"
  echo

  sleep 2
  echo "  import the bundle..."
  sleep 2
  MYCURL -X POST \
       "${mgmtserver}/v1/o/${org}/apis/?action=import&name=${apiname}" \
       -T ${apiname}.zip -H "Content-Type: application/octet-stream"
  if [ ${CURL_RC} -ne 201 ]; then
    echo
    echoerror "  failed importing that bundle."
    cat ${CURL_OUT}
    echo
    echo
    exit 1
  fi

  echo "  deploy the ${apiname} apiproxy..."
  sleep 2
  MYCURL -X POST \
  "${mgmtserver}/v1/o/${org}/apis/${apiname}/revisions/1/deployments?action=deploy&env=$env"
  if [ ${CURL_RC} -ne 200 ]; then
    echo
    echoerror "  failed deploying that api."
    cat ${CURL_OUT}
    echo
    echo
    exit 1
  fi
}


function create_new_product() {
  productname=${apiname}-`random_string`
  echo "  create a new product (${productname}) which contains that API proxy"
  sleep 2
  MYCURL \
    -H "Content-Type:application/json" \
    -X POST ${mgmtserver}/v1/o/${org}/apiproducts -d '{
   "approvalType" : "auto",
   "attributes" : [ ],
   "displayName" : "'${apiname}' Test product '${productname}'",
   "name" : "'${productname}'",
   "apiResources" : [ "/**" ],
   "description" : "Test for '${apiname}'",
   "environments": [ "'${env}'" ],
   "proxies": [ "'${apiname}'" ],
   "quota": "'${quotalimit}'",
   "quotaInterval": "1",
   "quotaTimeUnit": "minute"
  }'
  if [ ${CURL_RC} -ne 201 ]; then
    echo
    echo "  failed creating that product."
    cat ${CURL_OUT}
    echo
    echo
    exit 1
  fi

  MYCURL -X GET ${mgmtserver}/v1/o/${org}/apiproducts/${productname}

  if [ ${CURL_RC} -ne 200 ]; then
    echo
    echo "  failed querying that product."
    cat ${CURL_OUT}
    echo
    echo
    exit 1
  fi

  cat ${CURL_OUT}
  echo
  echo
}

function create_new_developer() {
  local shortdevname=${apiname}-`random_string`
  devname=${shortdevname}@apigee.com
  echo  "  create a new developer (${devname})..."
  sleep 2
  MYCURL -X POST \
    -H "Content-type:application/json" \
    ${mgmtserver}/v1/o/${org}/developers \
    -d '{
    "email" : "'${devname}'",
    "firstName" : "Dino",
    "lastName" : "Valentino",
    "userName" : "'${shortdevname}'",
    "organizationName" : "'${org}'",
    "status" : "active"
  }' 
  if [ ${CURL_RC} -ne 201 ]; then
    echo
    echo "  failed creating a new developer."
    cat ${CURL_OUT}
    echo
    echo
    exit 1
  fi
}

function create_new_app() {
  local payload
  appname=${apiname}-`random_string`
  echo  "  create a new app (${appname}) for that developer, with authorization for the product..."
  sleep 2

payload=$'{\n'
payload+=$'  "attributes" : [ {\n'
payload+=$'     "name" : "creator",\n'
payload+=$'     "value" : "provisioning script '
payload+="$0"
payload+=$'"\n'
payload+=$'    },{\n'
payload+=$'     "name" : "public_key",\n'
payload+=$'     "value" : "'
payload+="$publicKey"
payload+=$'"\n'
payload+=$'    } ],\n'
payload+=$'  "apiProducts": [ "'
payload+="${productname}"
payload+=$'" ],\n'
payload+=$'    "callbackUrl" : "thisisnotused://www.apigee.com",\n'
payload+=$'    "name" : "'
payload+="${appname}"
payload+=$'"\n'
#payload+=$'",\n'
#payload+=$'    "keyExpiresIn" : "100000000"\n'
payload+=$'}' 

#  pubkey=${pubkey// /\\ }
  # MYCURL -X POST \
  #   -H "Content-type:application/json" \
  #   ${mgmtserver}/v1/o/${org}/developers/${devname}/apps \
  #   -d '{
  #   "attributes" : [ {
  #         "name" : "creator",
  #         "value" : "provisioning script '$0'"
  #   },{
  #         "name" : "public_key",
  #         "value" : "'$pubkey'"
  #   } ],
  #   "apiProducts": [ "'${productname}'" ],
  #   "callbackUrl" : "thisisnotused://www.apigee.com",
  #   "name" : "'${appname}'",
  #   "keyExpiresIn" : "100000000"
  # }' 

  MYCURL -X POST \
    -H "Content-type:application/json" \
    ${mgmtserver}/v1/o/${org}/developers/${devname}/apps \
    -d "${payload}"

  if [ ${CURL_RC} -ne 201 ]; then
    echo
    echo "  failed creating a new app."
    cat ${CURL_OUT}
    echo
    echo
    exit 1
  fi
}

function retrieve_app_keys() {
  local array
  echo "  get the keys for that app..."
  sleep 2
  MYCURL -X GET \
    ${mgmtserver}/v1/o/${org}/developers/${devname}/apps/${appname} 

  if [ ${CURL_RC} -ne 200 ]; then
    echo
    echo "  failed retrieving the app details."
    cat ${CURL_OUT}
    echo
    echo
    exit 1
  fi  

  array=(`cat ${CURL_OUT} | grep "consumerKey" | sed -E 's/[",:]//g'`)
  consumerkey=${array[1]}
  array=(`cat ${CURL_OUT} | grep "consumerSecret" | sed -E 's/[",:]//g'`)
  consumersecret=${array[1]}

  echo "  consumer key: ${consumerkey}"
  echo "  consumer secret: ${consumersecret}"
  echo 
  sleep 2
}

echo
echo
echo "This script will create a vault named $vaultname, and will insert a private key "
echo "and its password into the vault. It will also create a new API Product, a new " 
echo "developer, and a new developer app with access to that product. It will place"
echo "the public key as an attribute to the developer app. "
echo
echo "=============================================================================="

while getopts "hm:o:e:f:p:b:u:nr" opt; do
  case $opt in
    h) usage ;;
    m) mgmtserver=$OPTARG ;;
    o) org=$OPTARG ;;
    e) env=$OPTARG ;;
    f) privkeyfile=$OPTARG ;;
    p) privkeypasswd=$OPTARG ;;
    b) pubkeyfile=$OPTARG ;;
    u) credentials=$OPTARG ;;
    n) netrccreds=1 ;;
    r) resetonly=1 ;;
    *) echo "unknown arg" && usage ;;
  esac
done


echo
if [ "X$mgmtserver" = "X" ]; then
  mgmtserver="$defaultmgmtserver"
fi 


if [ ${netrccreds} -eq 1 ]; then
  echo "using credentials from .netrc"
  credentials='-n'
elif [ "X$credentials" = "X" ]; then
    choose_credentials
elif [[ $credentials == *":"* ]]; then
    ## credentials contains a colon; its a username:password
  credentials="-u $credentials"
else
    # no colon; prompt for password
    choose_password $credentials
fi

echo
if [ "X$org" = "X" ]; then
  choose_org
else
  check_org 
  if [ ${check_org} -ne 0 ]; then
    echo "that org cannot be validated"
    CleanUp
    exit 1
  fi
fi 

echo
if [ "X$env" = "X" ]; then
  choose_env
fi


## reset everything related to this api
clear_env_state

if [ $resetonly -eq 0 ] ; then

  get_privatekey
  get_publickey

  deploy_new_bundle
  create_new_product
  create_new_developer
  create_new_app
  retrieve_app_keys

  echo
  echo inquire the vault $vaultname
  MYCURL $mgmtserver/v1/o/$org/e/$env/vaults/$vaultname
  if [ ${CURL_RC} -eq 500 ]; then
    echo the vault does not exist
    echo create the vault
    MYCURL -X POST -H content-type:application/json \
      $mgmtserver/v1/o/$org/e/$env/vaults \
      -d '{ "name": "'$vaultname'" }'
    if [ ${CURL_RC} -ne 201 ]; then
      echo failed.
      cat ${CURL_OUT} 
      echo
      exit
    fi
  elif [ ${CURL_RC} -eq 404 ]; then
    echo "Something went wrong"
    echo
    exit 1
  else
    echo the vault exists
    vaultexists=1
  fi

  if [ $vaultexists -ne 0 ]; then 
    delete_vault_entry_ifexists "$consumerkey"
    delete_vault_entry_ifexists "${consumerkey}-password"
  fi

  echo
  echo install the private key into the vault
  insert_vault_entry $consumerkey "$privateKey"

  echo
  echo install the private key password into the vault
  insert_vault_entry "${consumerkey}-password" "$privkeypasswd"

  echo 
  echo "use this apikey: ${consumerkey}"
  echo
fi



# cleanup
[ -f "${CURL_OUT}" ] && rm ${CURL_OUT}
