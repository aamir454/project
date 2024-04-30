#!/bin/bash
set -e

WORK_DIR=`cd $(dirname $0);pwd`
cd ${WORK_DIR}

DOCKER_FILE='1_tools/docker-20.10.9.tgz'
DOCKER_VERSION="20"
## DOCKERD_PARAMETER: add parameter for dockerd, 
# example: 
# if DOCKERD_PARAMETER="--data-root /Data/lib/docker"
# then dockerd start like this: /usr/bin/dockerd --data-root /Data/lib/docker
DOCKERD_PARAMETER=""

HARBOR_HOST="192.168.2.29"
HARBOR_IP="192.168.2.29"
HARBOR_HTTPS_PORT="9443"
HARBOR_DATA="/opt/data/harbor"
HARBOR_CA_PATH='harbor_certs/ca.crt'
HARBOR_ADMIN_PASSWORD='Harbor12345'

RANCHER_HOST="rancher.fluxble.com"
RANCHER_IP="192.168.2.29"
RANCHER_DATA="/opt/data/rancher"

METALLB_VIRTUAL_IP='192.168.2.230-192.168.2.231'

GITEA_IP='192.168.2.29'
GITEA_DATA="/opt/data/gitea"

LOKI_DEFAULT_STORAGE="80Gi"
LOKI_DOMAIN="loki.debug.com"

# MINIO_BACKUP_OBJECT_STORAGE_ENDPOINT='192.168.2.29:9000'
MINIO_BACKUP_DATA='/opt/minio/data'
MINIO_BACKUP_OBJECT_STORAGE_ACCESS_KEY='minio_access'
MINIO_BACKUP_OBJECT_STORAGE_SECRET_KEY='Tes9ting'

STS_NODE_NAME="k8s-worker-01 k8s-worker-02 k8s-worker-03 k8s-worker-04"


function showhelp(){
    echo "usage: $0  [--work_dir string]          default "$WORK_DIR""
    echo "       $0  [--env_file string]          default "$ENV_FILE""
    echo "       $0  [--harborhost string]        default "$HARBOR_HOST""
    echo "       $0  [--harborip string]          default "$HARBOR_IP""  
    echo "       $0  [--harbor_ca_path string ]   default "$HARBOR_CA_PATH"" 
    echo "       $0  [--docker_file string]       default "$DOCKER_FILE""
    echo "       $0  [--executeFunction function_name]   execute function_name, eg:--executeFunction listFunction"
    echo "       $0  removeDocker"
    echo "       $0  getReadyForHarbor"
    echo "       $0  cleanRancher"                 !!!important “will remove all the docker containers and volumes”
}

function listFunction(){
    cat "$0"| grep 'function'| grep '(){'|grep -v 'awk' |awk -F'function' '{print $NF}'|awk -F'{' '{print $1" "$NF}'
}

function CheckVMStatus(){
   echo "" > /tmp/VM_info
   uname -a >> /tmp/VM_info
   # docker -v >> /tmp/VM_info
   cat /proc/cpuinfo | grep name | cut -f2 -d: | uniq -c >> /tmp/VM_info
   free -mh >> /tmp/VM_info
   lsblk | grep sd >> /tmp/VM_info
   df -h | grep -v /var/lib | grep -v /dev/loop >> /tmp/VM_info
   cat /tmp/VM_info
}

function cleanRancher(){
    # read -r -p "will remove all the docker containers and volumes,Are You Sure? [Y/n] " input
    # if [ $input != Y ]; then
    # echo "exit cleanRancher"
    # exit 0
    # fi
    echo "cleanRancher now"    
    docker rm -f -v $(docker ps -aq)
    docker volume rm $(docker volume ls)
    umount $(df -HT | grep '/var/lib/kubelet/pods' | awk '{print $7}')
    umount $(df -HT | grep '/var/lib/kubelet/plugins' | awk '{print $7}')    
    rm -rf /var/lib/etcd
    rm -rf /var/lib/kubelet
    rm -rf  /var/lib/rancher
    rm -rf /etc/kubernetes
    echo "============cleanRancher Done============"
}

function disableFirewal(){
    echo "============disable firewal============"
    systemctl stop firewalld
    systemctl disable firewalld
    echo "============disable firewal Done============"
}

function disableSELinux(){
    echo "============disable SELinux============"
    getenforce
    setenforce 0
    sed -i "s/SELINUX=enforcing/SELINUX=disabled/g" /etc/selinux/config
    echo "============disable SELinux Done============"
}

function disableSwap(){
    echo "============disable Swap============"
    free -m
    swapoff -a
    sed -i 's/\(.*swap.*\)/# \1/g' /etc/fstab
    sed -i -e 's/# #/#/g' /etc/fstab
    sed -i -e '/net.ipv4.ip_nonlocal_bind/d' /etc/sysctl.conf
    echo "net.ipv4.ip_nonlocal_bind = 1" | sudo tee -a /etc/sysctl.conf

    sed -i -e '/net.ipv4.ip_forward/d' /etc/sysctl.conf
    echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf

    sed -i -e '/net.bridge.bridge-nf-call-ip6tables/d' /etc/sysctl.conf
    echo "net.bridge.bridge-nf-call-ip6tables = 1" | sudo tee -a /etc/sysctl.conf

    sed -i -e '/net.bridge.bridge-nf-call-iptables/d' /etc/sysctl.conf    
    echo "net.bridge.bridge-nf-call-iptables = 1" | sudo tee -a /etc/sysctl.conf

    sed -i -e '/vm.swappiness/d' /etc/sysctl.conf
    echo "vm.swappiness=0" | sudo tee -a /etc/sysctl.conf
    modprobe br_netfilter
    sysctl -p
    free -m
    echo "============disable Swap Done============"
}

function removeDocker(){
    which docker
    if [ $? -ne 0 ]; then
    echo "skip remove Docker"  
    else
    echo "============remove Docker===========" 
    DOCKER_BIN_PATH=`which docker`
    echo "mv ${DOCKER_BIN_PATH} ${DOCKER_BIN_PATH}_bak"
    # mv ${DOCKER_BIN_PATH}  ${DOCKER_BIN_PATH}_bak
    cp ${DOCKER_BIN_PATH}  ${DOCKER_BIN_PATH}_bak
    fi    
    echo "============remove Docker done============"
}

function installDocker(){
    echo "============install Docker==========="
    cd ${WORK_DIR}
    echo "check the DOCKER_FILE ${DOCKER_FILE}"
    if [ ! -f "${DOCKER_FILE}" ]; then
    echo " Error: No such file ${DOCKER_FILE} "
    exit 1
    else
    [ -d "/tmp/docker" ] && mv /tmp/docker /tmp/docker_`date +%s`
    tar zxvf ${DOCKER_FILE} -C /tmp/
    mv /tmp/docker/* /usr/bin/
    sudo tee /etc/systemd/system/docker.service << EOF
[Unit]

Description=Docker Application Container Engine

Documentation=https://docs.docker.com

After=network-online.target firewalld.service

Wants=network-online.target

[Service]

Type=notify

ExecStart=/usr/bin/dockerd ${DOCKERD_PARAMETER}

ExecReload=/bin/kill -s HUP $MAINPID

LimitNOFILE=infinity
LimitNPROC=infinity

TimeoutStartSec=0

Delegate=yes

KillMode=process

Restart=on-failure

StartLimitBurst=3

StartLimitInterval=60s

[Install]

WantedBy=multi-user.target

EOF

    chmod +x /etc/systemd/system/docker.service
    sudo systemctl daemon-reload
    sudo systemctl enable docker.service
    sudo systemctl start docker
    sudo docker -v
    echo "============install Docker Done==========="  
    fi
}

function getReadyForHarbor(){
    echo "============getReadyForHarbor============"
    echo "check the HARBOR_CA_PATH ${HARBOR_CA_PATH}"
    if [ ! -f "${HARBOR_CA_PATH}" ]; then
        echo " Error: No such file ${HARBOR_CA_PATH} "
        exit 1
    fi    
    mkdir -p /etc/docker/certs.d/${HARBOR_HOST}:${HARBOR_HTTPS_PORT}/
    cp "${HARBOR_CA_PATH}" /etc/docker/certs.d/${HARBOR_HOST}:${HARBOR_HTTPS_PORT}/ || echo "cp ${HARBOR_CA_PATH}/ca.crt failed."
    grep "$HARBOR_IP $HARBOR_HOST" /etc/hosts || echo "$HARBOR_IP $HARBOR_HOST" >> /etc/hosts
    grep "$RANCHER_IP $RANCHER_HOST" /etc/hosts || echo "$RANCHER_IP $RANCHER_HOST" >> /etc/hosts
    echo "restart docker" && sudo systemctl restart docker
    echo "============getReadyForHarbor Done============"
}

function loadSpecRancherImages(){
    echo "============loadSpecRancherImages============"
    docker pull ${HARBOR_HOST}:5443/rancher/shell:v0.1.5 
    docker pull ${HARBOR_HOST}:5443/rancher/kubectl:v1.18.6 
    docker tag ${HARBOR_HOST}:5443/rancher/shell:v0.1.5  rancher/shell:v0.1.5
    docker tag ${HARBOR_HOST}:5443/rancher/kubectl:v1.18.6 rancher/kubectl:v1.18.6
    echo "============loadSpecRancherImages Done============"
}

function installRancherLoadImagesScript(){
    echo "============installRancherLoadImagesScript============"
    sudo cp -v ${WORK_DIR}/rancher-load-images.sh /usr/local/bin/rancher-load-images.sh
    sudo chmod +x /usr/local/bin/rancher-load-images.sh
    echo "============installRancherLoadImagesScript Done============"
}

function installMC(){
    echo "============installMC============"
    sudo cp -v ${WORK_DIR}/1_tools/mc /usr/local/bin/mc
    sudo chmod +x /usr/local/bin/mc
    mc -v
    # mc config host add s3 https://s3.amazonaws.com $AWS_BUCKET_ACCESSKEY $AWS_BUCKET_SECRETKEY
    echo "============installMC Done============"
}

function installYq(){
    echo "============installYq============"
    sudo cp -v ${WORK_DIR}/1_tools/yq-3.4.1-linux-amd64 /usr/local/bin/yq
    sudo chmod +x /usr/local/bin/yq
    yq --version
    echo "============installYq Done============"
}
function installDockerCompose(){
    echo "============installDockerCompose============"
    sudo cp -v ${WORK_DIR}/1_tools/docker-compose-v1.27.4 /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    docker-compose -v
    echo "============installDockerCompose Done============"
}

function installHarbor(){
    echo "============installHarbor============"
    CN='self-signed.fluxble.com'
    CN_PROD=`echo ${HARBOR_HOST}`
    harbor_data=`echo ${HARBOR_DATA}`
    harbor_admin_password=`echo ${HARBOR_ADMIN_PASSWORD}`

    echo 'prepare certification'
    cd ${WORK_DIR}/tes_manifests/k8s_debug/ssl/harbor

    echo "self-sign certification for Harbor"
    openssl genrsa -out $CN_PROD.key 4096
    openssl req -new  -subj "/C=CN/ST=JS/L=WX/O=zwx/OU=otms/CN=${CN_PROD}" -nodes  -key $CN_PROD.key  -out $CN_PROD.csr
    echo "subjectAltName = IP:${CN_PROD}" > $CN_PROD.conf
    openssl x509 -req -days 3650  -in $CN_PROD.csr -CA $CN-ca.crt  -CAkey $CN-ca.key -CAcreateserial  -extfile $CN_PROD.conf  -out $CN_PROD.cert

    # check certs detail
    openssl x509 -text -noout -in $CN_PROD.cert

    # copy self-signed certificates to cert directory of harbor data path
    mkdir -p "${harbor_data}"/cert/
    cp -v ${CN_PROD}.cert "${harbor_data}"/cert/harbor.cert
    cp -v ${CN_PROD}.key "${harbor_data}"/cert/harbor.key
    echo "generate configuration"
    cd ${WORK_DIR}/1_tools
    [ -d "harbor" ]&& mv harbor harbor_`date +%s`
    tar xzvf harbor-offline-installer-v2.4.1.tgz -C .
    cd harbor
    cp -v harbor.yml.tmpl harbor.yml
    yq w -i "harbor.yml" "hostname" "${CN_PROD}"
    yq w -i "harbor.yml" "http.port" "9080"
    yq w -i "harbor.yml" "https.port" "${HARBOR_HTTPS_PORT}"
    yq w -i "harbor.yml" "https.certificate" "${harbor_data}/cert/harbor.cert"
    yq w -i "harbor.yml" "https.private_key" "${harbor_data}/cert/harbor.key"
    yq w -i "harbor.yml" "data_volume" "${harbor_data}"
    yq w -i "harbor.yml" "harbor_admin_password" ${harbor_admin_password}
    echo "start..."
    bash ./install.sh --with-chartmuseum --with-trivy
    echo "============installHarbor Done============"
}

function addProjectsToHarbor(){
    echo "============addProjectsToHarbor============"
    projects=`echo '
    bats
    bitnami
    docker.elastic.co
    gcr.io
    ghcr.io
    gitea
    grafana
    istio
    k8s.gcr.io
    lachlanevenson
    longhornio
    quay.io
    rancher
    registry.tespkg.in
    '`
    for project in ${projects[@]};do
        echo $project
        curl "https://${HARBOR_HOST}:${HARBOR_HTTPS_PORT}/api/v2.0/projects" \
            -d "{\"project_name\": \"${project}\", \"public\": true, \"storage_limit\": 0}" \
            -u "admin:${HARBOR_ADMIN_PASSWORD}" \
            -H 'Content-Type: application/json' \
            --compressed \
            --insecure
        sleep 1
    done
    echo "============addProjectsToHarbor Done============"
}

function addSelfCAForDocker(){
    echo "============addSelfCAForDocker============"
    CN='self-signed.fluxble.com'

    sudo mkdir -p "/etc/docker/certs.d/${HARBOR_HOST}:${HARBOR_HTTPS_PORT}/"
    sudo cp -v ${WORK_DIR}/tes_manifests/k8s_debug/ssl/harbor/$CN-ca.crt "/etc/docker/certs.d/${HARBOR_HOST}:${HARBOR_HTTPS_PORT}/"
    echo "============addSelfCAForDocker Done============"
}

function installRancher(){
    echo "============installRancher============"
    echo 'load image'
    component="rancher-${Rancher_Version:-v2.6.3}"
    sudo docker load -i ${WORK_DIR}/2_images/k8s/${component}-images.tar.gz
    is_rancher_running=`docker ps -a|grep 'rancher:'| wc -l`
    [ $is_rancher_running = 1 ]&& echo 'existing rancher,stopping...' &&docker stop rancher&& docker rm rancher
    echo 'Start...'
    sudo docker run -d --name rancher --privileged --restart=unless-stopped \
    -v ${RANCHER_DATA}:/var/lib/rancher \
    -p 80:80 -p 443:443 \
    rancher/rancher:${Rancher_Version:-v2.6.3}
    echo `docker logs rancher 2>&1 | grep "Bootstrap Password:"`
    echo "============installRancher Done============"
}

function LoadRKEImage(){
    echo "============LoadRKEImage============"
    echo 'load image'
    cd ${WORK_DIR}/2_images/k8s/
    component="${RKE_Version:-rkev1-1.19}"
    docker login ${HARBOR_HOST}:${HARBOR_HTTPS_PORT} -u admin -p "${HARBOR_ADMIN_PASSWORD}"
    sudo rancher-load-images.sh -l ${component}-images.txt --images ${component}-images.tar.gz --registry ${HARBOR_HOST}:${HARBOR_HTTPS_PORT}
    echo "============LoadRKEImage Done============"
}

function installGitea(){
    echo "============installGitea============"
    cd ${WORK_DIR}/2_images/gitops
    HARBOR_HOST=`echo $HARBOR_HOST:$HARBOR_HTTPS_PORT`
    component=gitea-1.15.7
    echo 'load image to Harbor'
    sudo rancher-load-images.sh -l ${component}-images.txt --images ${component}-images.tar.gz --registry ${HARBOR_HOST}
    mkdir -p ${GITEA_DATA}
    cd "${GITEA_DATA}"
    sudo tee gitea-docker-compose.yaml <<EOF
version: "3"
networks:
  gitea:
    external: false
services:
  server:
    image: ${HARBOR_HOST}/gitea/gitea:1.15.7
    container_name: gitea
    environment:
    - USER_UID=1000
    - USER_GID=1000
    restart: always
    networks:
    - gitea
    volumes:
    - $GITEA_DATA:/data
    - /etc/timezone:/etc/timezone:ro
    - /etc/localtime:/etc/localtime:ro
    ports:
    - "3000:3000"
    - "222:22"
EOF
    sudo sed -i -e 's/\$GITEA_DATA/$GITEA_DATA/' gitea-docker-compose.yaml
    if [ -n "$(sudo docker-compose -f gitea-docker-compose.yaml ps -q)" ]
    then
        echo "stopping existing Harbor instance ..."
        sudo docker-compose -f gitea-docker-compose.yaml down -v
    fi
    [ -n "$(sudo docker ps -a|grep gitea)" ] && echo "existing Gitea instance, stopping..." && sudo docker stop gitea && sudo docker rm gitea
    echo "start..."
    sudo docker-compose -f gitea-docker-compose.yaml up -d
    echo 'please initial gitea Configuration manually via gitea web UI'
    echo "============installGitea Done============"
}

function installMinioBackup(){
    echo "============installMinioBackup============"
    cd "${WORK_DIR}/2_images/dr"
    component='minio-RELEASE.2021-12-29T06-49-06Z'
    echo 'load image to Harbor'
    HARBOR_HOST=`echo $HARBOR_HOST:$HARBOR_HTTPS_PORT`
    rancher-load-images.sh -l ${component}-images.txt --images ${component}-images.tar.gz  --registry ${HARBOR_HOST}
    [ -n "$(sudo docker ps -a |grep minio)" ] && echo 'exists minio, stopping...'&&sudo docker stop minio && sudo docker rm minio
    echo "start..."
    sudo docker run -p 9000:9000 -p 9001:9001 \
    --name minio -d --restart=always  \
    -e "MINIO_ROOT_USER=${MINIO_BACKUP_OBJECT_STORAGE_ACCESS_KEY}" \
    -e "MINIO_ROOT_PASSWORD=${MINIO_BACKUP_OBJECT_STORAGE_SECRET_KEY}" \
    -v "${MINIO_BACKUP_DATA}":/data \
    ${HARBOR_HOST}/quay.io/minio/minio:RELEASE.2021-12-29T06-49-06Z server /data --console-address ":9001"
    echo "============installMinioBackup Done============"
}

function installHelm(){
    echo "============installHelm============"
    echo "install helm binary"
    cd "${WORK_DIR}/1_tools/"
    tar -zxvf helm-v3.4.2-linux-amd64.tar.gz -C /tmp/
    sudo mv /tmp/linux-amd64/helm /usr/local/bin/helm
    sudo chmod +x /usr/local/bin/helm
    helm version
    echo "install helm plugin helm-push"
    tar -zxvf helm-push_0.9.0_linux_amd64.tar.gz -C /tmp/
    # rm -rf ~/.local/share/helm/plugins/*
    mkdir -p ~/.local/share/helm/plugins/helm-push
    cp -v /tmp/plugin.yaml ~/.local/share/helm/plugins/helm-push/
    cp -r -v /tmp/bin ~/.local/share/helm/plugins/helm-push/
    echo "============installHelm Done============"
}

function installHelmfile(){
    echo "============installHelmfile============"
    sudo cp -v "${WORK_DIR}"/1_tools/helmfile-v0.139.4-linux-amd64 /usr/local/bin/helmfile
    sudo chmod +x /usr/local/bin/helmfile
    helmfile -v
    echo "============installHelmfile Done============"
}

function installJq(){
    echo "============installJq============"
    sudo cp -v "${WORK_DIR}"/1_tools/jq-1.6-linux64 /usr/local/bin/jq
    sudo chmod +x /usr/local/bin/jq
    jq --version
    echo "============installJq Done============"
}

function installKubeCLI(){
    echo "============installKubeCLI============"
    sudo cp -v "${WORK_DIR}"/1_tools/kubectl-v1.23.4-linux-amd64 /usr/local/bin/kubectl
    sudo cp -v "${WORK_DIR}"/1_tools/kubectx /usr/local/bin/kubectx
    sudo cp -v "${WORK_DIR}"/1_tools/kubens /usr/local/bin/kubens
    sudo chmod +x /usr/local/bin/kube*
    echo "============installKubeCLI Done============"
}

function installArgoCLI(){
    echo "============installArgoCLI============"
    sudo cp -v "${WORK_DIR}"/1_tools/argocd-v2.2.1-linux-amd64 /usr/local/bin/argocd
    sudo chmod +x /usr/local/bin/argocd
    echo "============installArgoCLI Done============"
}

function installPgoCLI(){
    echo "============installPgoCLI============"
    sudo cp -v "${WORK_DIR}"/1_tools/pgo /usr/local/bin/pgo
    sudo chmod +x /usr/local/bin/pgo
    # pgo version
    echo "============installPgoCLI Done============"
}

function prepareKubeConfig(){
    # refer: https://docs.rancher.cn/docs/rancher2.5/cluster-admin/restore-kubecfg/_index/
    echo "============prepareKubeConfig============"
    K8S_MASTER_NODE_IP='127.0.0.1'
    # get Rancher Agent image name
    RANCHER_IMAGE=$( docker images --filter=label=io.cattle.agent=true |grep 'v2.' | \
    grep -v -E 'rc|alpha|<none>' | head -n 1 | awk '{print $3}' )

    if [ -d /opt/rke/etc/kubernetes/ssl ]; then
    K8S_SSLDIR=/opt/rke/etc/kubernetes/ssl
    else
    K8S_SSLDIR=/etc/kubernetes/ssl
    fi

    CHECK_CLUSTER_STATE_CONFIGMAP=$( docker run --rm --entrypoint bash --net=host \
    -v $K8S_SSLDIR:/etc/kubernetes/ssl:ro $RANCHER_IMAGE -c '\
    if kubectl --kubeconfig /etc/kubernetes/ssl/kubecfg-kube-node.yaml \
    -n kube-system get configmap full-cluster-state | grep full-cluster-state > /dev/null; then \
    echo 'yes'; else echo 'no'; fi' )

    if [ $CHECK_CLUSTER_STATE_CONFIGMAP != 'yes' ]; then

    docker run --rm --net=host \
    --entrypoint bash \
    -e K8S_MASTER_NODE_IP=$K8S_MASTER_NODE_IP \
    -v $K8S_SSLDIR:/etc/kubernetes/ssl:ro \
    $RANCHER_IMAGE \
    -c '\
    kubectl --kubeconfig /etc/kubernetes/ssl/kubecfg-kube-node.yaml \
    -n kube-system \
    get secret kube-admin -o jsonpath={.data.Config} | base64 --decode | \
    sed -e "/^[[:space:]]*server:/ s_:.*_: \"https://${K8S_MASTER_NODE_IP}:6443\"_"' > kubeconfig_admin.yaml

    if [ -s kubeconfig_admin.yaml ]; then
        echo 'restore kubeconfig successfully'
        sudo mkdir -p ~/.kube
        [ -f ~/.kube/config ] && sudo cp -v ~/.kube/config ~/.kube/config_`date +%s`
        sudo cp -v kubeconfig_admin.yaml ~/.kube/config
    else
        echo "restore kubeconfig failed"
    fi

    else

    docker run --rm --entrypoint bash --net=host \
    -e K8S_MASTER_NODE_IP=$K8S_MASTER_NODE_IP \
    -v $K8S_SSLDIR:/etc/kubernetes/ssl:ro \
    $RANCHER_IMAGE \
    -c '\
    kubectl --kubeconfig /etc/kubernetes/ssl/kubecfg-kube-node.yaml \
    -n kube-system \
    get configmap full-cluster-state -o json | \
    jq -r .data.\"full-cluster-state\" | \
    jq -r .currentState.certificatesBundle.\"kube-admin\".config | \
    sed -e "/^[[:space:]]*server:/ s_:.*_: \"https://${K8S_MASTER_NODE_IP}:6443\"_"' > kubeconfig_admin.yaml

    if [ -s kubeconfig_admin.yaml ]; then
        echo 'restore kubeconfig successfully'
        sudo mkdir -p ~/.kube
        [ -f ~/.kube/config ] && sudo cp -v ~/.kube/config ~/.kube/config_`date +%s`
        sudo cp -v kubeconfig_admin.yaml ~/.kube/config
    else
        echo "restore kubeconfig failed"
    fi
    fi
    echo "============prepareKubeConfig Done============"
}

function labelStsNode(){
    for node_name in ${STS_NODE_NAME[@]};do
	    echo ${node_name}
        kubectl label --overwrite node ${node_name} lifecycle=sts
    done
}

function installMetallb(){
    echo "============installMetallb============"
    cd "${WORK_DIR}"/2_images/network/
    echo 'load image'
    virtual_ips=`echo $METALLB_VIRTUAL_IP`
    HARBOR_HOST=`echo $HARBOR_HOST:$HARBOR_HTTPS_PORT`
    component='metallb-0.11.0-debian-10-r0'
    rancher-load-images.sh -l ${component}-images.txt --images ${component}-images.tar.gz  --registry ${HARBOR_HOST}
    echo 'prepare configuration'
    cd "${WORK_DIR}"/tes_manifests/helm-tps/metallb/
    sed -i -e "s#172.31.28.173#${virtual_ips}#" out-offline.yaml
    is_ns_exists=`kubectl get ns |grep metallb|wc -l`
    if [ $is_ns_exists = 0 ];then
    kubectl create ns metallb
    fi
    sed -i -e "s#docker.io#${HARBOR_HOST}#" out-offline.yaml
    echo 'start...'
    kubectl -n metallb apply -f out-offline.yaml
    kubectl -n metallb get po
    echo "============installMetallb Done============"
}

function installIstio(){
    echo "============installIstio============"
    cd "${WORK_DIR}"/2_images/network/
    echo 'Load image'
    component='istio-1.3.6'
    HARBOR_HOST=`echo $HARBOR_HOST:$HARBOR_HTTPS_PORT`
    rancher-load-images.sh -l ${component}-images.txt --images ${component}-images.tar.gz --registry ${HARBOR_HOST}
    echo 'install istio init'
    cd "${WORK_DIR}"/tes_manifests/helm-tps/istio-init/
    sed -i -e "s#docker.io#${HARBOR_HOST}#g" out.yaml
    is_ns_exists=`kubectl get ns |grep istio-system|wc -l`
    if [ $is_ns_exists = 0 ];then
        kubectl create ns istio-system
    fi
    kubectl -n istio-system apply -f out.yaml
    sleep 30
    echo `install istio`
    cd "${WORK_DIR}"/tes_manifests/helm-tps/istio/
    sed -i -e "s#docker.io#${HARBOR_HOST}#" out.yaml
    kubectl -n istio-system apply -f out.yaml
    kubectl -n istio-system get po
    kubectl -n istio-system get svc
    echo "============installIstio Done============"
}

function testIstio(){
    echo "============testIstio============"
    component='echoserver-1.8'
    cd "${WORK_DIR}"/2_images/network/
    echo 'Load image'
    HARBOR_HOST=`echo $HARBOR_HOST:$HARBOR_HTTPS_PORT`
    rancher-load-images.sh -l ${component}-images.txt --images ${component}-images.tar.gz --registry ${HARBOR_HOST}
    echo 'create debug gateway'
    cat <<EOF | kubectl apply -f -
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: debug-gateway
  namespace: default
spec:
  selector:
    istio: ingressgateway
  servers:

  - hosts:
    - '*.debug.com'
    - debug.com
    port:
      name: http
      number: 80
      protocol: HTTP
EOF
    echo 'create namesapce debug-only'
    is_ns_exists=`kubectl get ns |grep debug-only|wc -l`
    if [ $is_ns_exists = 0 ];then
        kubectl create ns debug-only
    fi
    echo 'start echo server'
cat <<EOF | kubectl -n debug-only apply -f -
# Source: CHANGEME_CHART_NAME/templates/secrets-registry.gitlab.com.yaml
apiVersion: v1
kind: Secret
metadata:
  name: echoserver-gitlabregistrykey
  labels:
    app: CHANGEME_CHART_NAME
    release: "echoserver"
    heritage: "Helm"
type: "kubernetes.io/dockercfg"
data:
  .dockercfg: eyJodHRwczovL3JlZ2lzdHJ5LmdpdGxhYi5jb20iOnsidXNlcm5hbWUiOiJyZWdpc3RyeV9yd19hY2Nlc3Nfa2V5IiwicGFzc3dvcmQiOiItdEdzY3l4azRvUHRoUExaR3hVRSIsImVtYWlsIjoiIiwiYXV0aCI6ImNtVm5hWE4wY25sZmNuZGZZV05qWlhOelgydGxlVG90ZEVkelkzbDRhelJ2VUhSb1VFeGFSM2hWUlE9PSJ9fQ==
---
# Source: CHANGEME_CHART_NAME/charts/common/templates/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: echoserver
  labels:
    app: echoserver
    release: echoserver
    heritage: Helm
spec:
  type: ClusterIP
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  selector:
    app: echoserver
    # release: echoserver
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echoserver
  labels:
    app: echoserver
    version: "1.8"
    release: echoserver
    heritage: Helm
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echoserver
      release: echoserver
  template:
    metadata:
      annotations: 
        {}
      labels:
        app: echoserver
        release: echoserver
        version: "1.8"
        env: dev-meeraspace
    spec:
      imagePullSecrets:
      - name: echoserver-gitlabregistrykey
      containers:
        - name: echoserver
          image: "${HARBOR_HOST}/gcr.io/google-containers/echoserver:1.8"
          imagePullPolicy: IfNotPresent          
          env:
          command:          
          ports:
          - containerPort: 8080
            name: http
            protocol: TCP
          resources:
            {}  
          livenessProbe:
            null
          readinessProbe:
            null
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: echoserver
spec:
  hosts:
  - echoserver.debug.com
  gateways: 
  - default/debug-gateway
  http:
  - match:
    - uri:
        prefix: /
    route:
    - destination:
        host: echoserver
        port:
          number: 8080
EOF
    echo 'add istio_ingressgateway_svc_ip echoserver.debug.com -> /etc/hosts'
    istio_ingressgateway_svc_ip=`kubectl -n istio-system get svc istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}'`
    echo "${istio_ingressgateway_svc_ip} echoserver.debug.com" | sudo tee -a /etc/hosts -
    cat /etc/hosts
    echo 'try to access http://echoserver.debug.com'
    curl 'http://echoserver.debug.com'
    echo "============testIstio Done============"
}

function installLonghorn(){
    echo "============installLonghorn============"
    cd "${WORK_DIR}"/2_images/volume/
    echo 'Load image'
    component='longhornio-v1.2.3'
    HARBOR_HOST=`echo $HARBOR_HOST:$HARBOR_HTTPS_PORT`
    rancher-load-images.sh -l ${component}-images.txt --images ${component}-images.tar.gz  --registry ${HARBOR_HOST}
    echo 'prepare configuration'
    cd "${WORK_DIR}"/tes_manifests/helm-tps/longhorn/
    sed -i -e "s#image: longhornio#image: $HARBOR_HOST/longhornio#" out.yaml
    sed -i -e "s#\"longhornio/#\"$HARBOR_HOST/longhornio/#" out.yaml
    echo 'start...'
    is_ns_exists=`kubectl get ns |grep longhorn-system|wc -l`
    if [ $is_ns_exists = 0 ];then
        kubectl create ns longhorn-system
    fi
    kubectl apply -f out.yaml
    # sleep 5
    # kubectl -n longhorn-system get po
    sleep 60
    kubectl apply -f out.yaml
    # sleep 5
    # kubectl -n longhorn-system get po
    #echo 'note: must run kubectl apply -f out.yaml twice to make sure success'
    echo "============installLonghorn Done============"
}

function installArgoCD(){
    echo "============installArgoCD============"
    cd "${WORK_DIR}"/2_images/gitops/
    echo 'Load image'
    component='argocd-v2.2.1'
    HARBOR_HOST=`echo $HARBOR_HOST:$HARBOR_HTTPS_PORT`
    rancher-load-images.sh -l ${component}-images.txt --images ${component}-images.tar.gz  --registry ${HARBOR_HOST}
    echo 'prepare configuration'
    cd "${WORK_DIR}"/tes_manifests/helm-tps/argocd/g-argocd/
    sed -i -e "s#image: ghcr.io#image: ${HARBOR_HOST}/ghcr.io#" install.yaml
    sed -i -e "s#image: quay.io#image: ${HARBOR_HOST}/quay.io#" install.yaml
    sed -i -e "s#image: haproxy#image: ${HARBOR_HOST}/rancher/haproxy#" install.yaml
    sed -i -e "s#image: redis#image: ${HARBOR_HOST}/rancher/redis#" install.yaml
    echo 'start...'
    is_ns_exists=`kubectl get ns |grep argocd|wc -l`
    if [ $is_ns_exists = 0 ];then
        kubectl create ns argocd
    fi
    kubectl -n argocd apply -f install.yaml
    echo 'create cm argocd-cm'
    cat <<EOF | kubectl -n argocd apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  labels:
    app.kubernetes.io/name: argocd-cm
    app.kubernetes.io/part-of: argocd
  name: argocd-cm
EOF
    echo 'create secret argocd-secret'
    cat <<EOF | kubectl -n argocd apply -f -
apiVersion: v1
kind: Secret
metadata:
  labels:
    app.kubernetes.io/name: argocd-secret
    app.kubernetes.io/part-of: argocd
  name: argocd-secret
type: Opaque
EOF
    echo 'set default argocd account: admin/A123456'
    kubectl -n argocd patch secret argocd-secret -p '{"stringData": { "admin.password": "$2a$10$88NHgAw3gSbPmMGvPH8wl.E.wh/JpxF6LpAkN.3YzI8vCKqz92rpi","admin.passwordMtime": "'$(date +%FT%T%Z)'" }}'
    kubectl -n argocd get po
    # echo 'login argocd via CLI'
    # argocd_server=`kubectl -n argocd get svc argocd-server -o jsonpath='{.spec.clusterIP}'`
    # argocd login ${argocd_server}  --username admin --password A123456
    echo 'please add git repo, execute command: argocd repo add ${git_repo_url} --insecure-ignore-host-key --ssh-private-key-path ~/.ssh/id_rsa'
    echo 'please set password to Tes9ting, execute command: argocd account update-password --account admin --current-password A123456'
    echo "============installArgoCD Done============"
}

function debugArgoCD(){
    echo "============debugArgoCD============"
    git_repo_url=`echo "ssh://git@${GITEA_IP}:222/tespkg/tes_manifests.git"`
    HARBOR_HOST=`echo $HARBOR_HOST:$HARBOR_HTTPS_PORT`
    cd "${WORK_DIR}"/tes_manifests
    git init
    git add .
    git config user.email "`whoami`@`hostname`.com"
    git config user.name "`whoami`"
    git commit -a -m "first commit"
    git remote add origin "${git_repo_url}"
    git push -u origin master

    sed -i -e "s#repository: gcr.io#repository: ${HARBOR_HOST}/gcr.io#" env-debug/echoserver/values.yaml
    sed -i -e "s#git@github.com:tespkg/tes_manifests.git#${git_repo_url}#" argocd_helmfile/all-charts/parent-apps/values.yaml
    sed -i -e "s#git@github.com:tespkg/tes_manifests.git#${git_repo_url}#"  argocd_helmfile/environments/debug/values.yaml
    git commit -a -m "update git repo"
    git push

    cd argocd_helmfile
    sh render.sh debug
    git add gitops
    git commit -a -m "render debug"
    git push
    kubectl apply -f gitops/debug/parent-apps/argocd/templates/1-paraent-Application.yaml
    echo 'please login ArgoCD web UI, check applications status'
    echo "============debugArgoCD Done============"
}

function installLoki(){
    echo "============installLoki============"
    cd "${WORK_DIR}"/2_images/logging-monitoring-tracing/
    echo 'Load image'
    HARBOR_HOST=`echo $HARBOR_HOST:$HARBOR_HTTPS_PORT`
    component='loki-2.4.1'
    rancher-load-images.sh -l ${component}-images.txt --images ${component}-images.tar.gz  --registry ${HARBOR_HOST}
    echo 'prepare configuration'
    storage=`echo $LOKI_DEFAULT_STORAGE`
    loki_domain=`echo $LOKI_DOMAIN`
    new_tag='2.4.1'
    cd "${WORK_DIR}"/tes_manifests/helm-tps/loki-stack/
    sed -i -e "s#loki.dev.meeraspace.com#${loki_domain}#" values-dev.yaml
    sed -i -e "s#repository: grafana/loki#repository: ${HARBOR_HOST}/grafana/loki#" values-dev.yaml
    sed -i -e "s#repository: grafana/promtail#repository: ${HARBOR_HOST}/grafana/promtail#" values-dev.yaml
    sed -i -e "s#tag: 2.2.1#tag: ${new_tag}#" values-dev.yaml
    helm template loki-stack . -f values-dev.yaml --namespace=logging > out.yaml
    sed -i -e "s#image: bats/bats:v1.1.0#image: ${HARBOR_HOST}/bats/bats:v1.1.0#" out.yaml
    echo 'start ...'
    is_ns_exists=`kubectl get ns |grep logging|wc -l`
    if [ $is_ns_exists = 0 ];then
        kubectl create ns logging
    fi
    kubectl -n logging apply -f out.yaml
    kubectl -n logging get po
    echo "============installLoki Done============"
}

function installPrometheus(){
    echo "============installPrometheus============"
    cd "${WORK_DIR}"/2_images/logging-monitoring-tracing/
    echo 'Load image'
    component='prometheus-stack-19.2.2'
    HARBOR_HOST=`echo $HARBOR_HOST:$HARBOR_HTTPS_PORT`
    rancher-load-images.sh -l ${component}-images.txt --images ${component}-images.tar.gz  --registry ${HARBOR_HOST}
    echo 'install crds'
    cd "${WORK_DIR}"/tes_manifests/helm-tps/prometheus/kube-prometheus-stack/
    kubectl apply -f ./crds/
    echo 'prepare configuration'
    sed -i -e "s#image: k8s.gcr.io/ingress-nginx/kube-webhook-certgen:v1.0@sha256:f3b6b39a6062328c095337b4cadcefd1612348fdd5190b1dcbcb9b9e90bd8068#image: ${HARBOR_HOST}/k8s.gcr.io/ingress-nginx/kube-webhook-certgen:v1.0#" out_offine.yaml
    sed -i -e "s#image: \"quay.io#image: \"${HARBOR_HOST}/quay.io#" out_offine.yaml
    sed -i -e "s#: quay.io#: ${HARBOR_HOST}/quay.io#" out_offine.yaml
    sed -i -e "s#image: \"k8s.gcr.io#image: \"${HARBOR_HOST}/k8s.gcr.io#" out_offine.yaml
    sed -i -e "s#image: k8s.gcr.io#image: ${HARBOR_HOST}/k8s.gcr.io#" out_offine.yaml
    sed -i -e "s#image: \"grafana#image: \"${HARBOR_HOST}/grafana#" out_offine.yaml
    sed -i -e "s#image: \"bats#image: \"${HARBOR_HOST}/bats#" out_offine.yaml
    sed -i -e "s#=quay.io#=${HARBOR_HOST}/quay.io#" out_offine.yaml
    echo 'start...'
    is_ns_exists=`kubectl get ns |grep cattle-monitoring-system|wc -l`
    if [ $is_ns_exists = 0 ];then
        kubectl create ns cattle-monitoring-system
    fi
    kubectl apply -f out_offine.yaml
#     # create secret for thanos: thanos dependency s3,so we need to create a bucket and relevant access_key,secret_key
#     OBJECT_STORAGE_ENDPOINT=`echo $MINIO_BACKUP_OBJECT_STORAGE_ENDPOINT`
#     OBJECT_STORAGE_BUCKET=`echo $PROMETHEUS_THANOS_OBJECT_STORAGE_BUCKET`
#     OBJECT_STORAGE_ACCESS_KEY=`echo $MINIO_BACKUP_OBJECT_STORAGE_ACCESS_KEY`
#     OBJECT_STORAGE_SECRET_KEY=`echo $MINIO_BACKUP_OBJECT_STORAGE_SECRET_KEY`

#     tee object-store.yaml <<EOF
# config:
#   access_key: ${OBJECT_STORAGE_ACCESS_KEY}
#   bucket: ${OBJECT_STORAGE_BUCKET}
#   endpoint: ${OBJECT_STORAGE_ENDPOINT}
#   secret_key: ${OBJECT_STORAGE_SECRET_KEY}
#   region: ""
# type: S3
# EOF
#     kubectl -n cattle-monitoring-system create secret generic thanos --from-file=object-store.yaml=object-store.yaml
#     kubectl -n cattle-monitoring-system get po
    echo "============installPrometheus Done============"
}

while [[ $# > 0 ]]
do
key="$1"

case $key in
    --work_dir)
    WORK_DIR="$2"
    # cd ${WORK_DIR}
    shift
    ;;
    --env_file)
    env_file="$2"
    source "$env_file"
    shift
    ;;    
    --harborhost)
    HARBOR_HOST="$2"
    shift
    ;;
    --harborip)
    HARBOR_IP="$2"
    shift
    ;;
    --harbor_ca_path)
    HARBOR_CA_PATH="$2"
    shift
    ;;
    --docker_file)
    DOCKER_FILE="$2"
    shift
    ;;
    disableFirewal)
    disableFirewal="true"
    shift # past argument
    ;;
    disableSELinux)
    disableSELinux="true"
    shift # past argument
    ;;
    removeDocker)
    removeDocker="true"
    shift # past argument
    ;;
    cleanRancher)
    cleanRancher="true"
    shift # past argument
    ;;
    --cmsport)
    CMSPORT="$2"
    shift
    ;;
    clean)
    CLEAN=true
    ;;
    getReadyForHarbor)
    getReadyForHarbor=true
    ;;
    --executeFunction)
    executeFunction="$2"
    ;;
    *)
         # unknown option
    ;;
esac
ARGS=true
shift # past argument or value
done

if [ "$ARGS" == "" ]
    then
    showhelp
    exit 0
fi

if [ "$disableFirewal" == true ]
    then
    disableFirewal
    exit 0
fi

if [ "$disableSELinux" == true ]
    then
    disableSELinux
    exit 0
fi

if [ "$removeDocker" == true ]
    then
    removeDocker
    exit 0
fi

if [ "$cleanRancher" == true ]
    then
    cleanRancher
    exit 0
fi

if [ "$getReadyForHarbor" == true ]
    then
    getReadyForHarbor
    exit 0
fi
if [ "$executeFunction" ];then
    $executeFunction
fi

# docker -v | grep $DOCKER_VERSION
# if [ $? -ne 0 ]; then
#   removeDocker
#   installDocker
# else
#   echo "skip install Docker"  
# fi

#disableFirewal

#disableSELinux

#setupHarborCerts

#loadSpecRancherImages