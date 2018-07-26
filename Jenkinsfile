node {
    stage "pull dockerfiles"
    git branch: 'master', credentialsId: 'gitlab', url: 'http://scc-gitlab-1.dev.octanner.net/cobra/oct-rabbitmq-api.git'
    
    registry_url    = "https://quay.octanner.io"
    docker_creds_id = "quay.octanner.io-cloudops"
    org_name        = "cloudops"

    stage "build image"

    docker.withRegistry("${registry_url}", "${docker_creds_id}") {
        build_tag = "1.0.${env.BUILD_NUMBER}"
        container_name = "oct-rabbitmq-api"
        container = docker.build("${org_name}/${container_name}:${build_tag}")
        
        container.push()
        container.push 'latest'
    }

}
