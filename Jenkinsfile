pipeline {
    agent any

    environment {
        GIT_CREDENTIALS_ID = 'github-creds' 
        DOCKER_CREDENTIALS = 'docker-cred'
        REGISTRY = 'mrunmayi12'
        ML_IMAGE = "${REGISTRY}/ml-service:latest"
        PREPROCESS_IMAGE = "${REGISTRY}/preprocessing-service:latest"
        CAPTURE_IMAGE = "${REGISTRY}/capture-service:latest"
        FRONTEND_IMAGE = "${REGISTRY}/frontend-service:latest"
        SIMULATOR_IMAGE = "${REGISTRY}/simulator-service:latest"
        KUBECONFIG = "/var/lib/jenkins/.kube/config"
    }

    stages {
        stage('Checkout') {
            steps {
                git url: 'https://github.com/Mrunmayii/Intrusion-Detection-System-MLOps.git',
                credentialsId: GIT_CREDENTIALS_ID,
                branch: 'main'
            }
        }

        stage('Ansible Provisioning') {
            steps {
                withCredentials([string(credentialsId: 'ansible-vault-pass', variable: 'VAULT_PASS')]) {
                    dir('ansible') {
                        sh '''
                        echo "$VAULT_PASS" > vault-pass.txt
                        ansible-playbook setup-infra.yml
                        ansible-playbook k8s-setup.yml
                        ansible-playbook monitoring-setup.yml --vault-password-file vault-pass.txt
                        rm vault-pass.txt
                        '''
                    }
                }
            }
        }


        stage('Build Docker Images') {
            steps {
                script {
                    docker.build(ML_IMAGE, './ml-service')
                    docker.build(PREPROCESS_IMAGE, './preprocessing-service')
                    docker.build(CAPTURE_IMAGE, './packet-capture-service')
                    docker.build(FRONTEND_IMAGE, './frontend-service')
                    docker.build(SIMULATOR_IMAGE, './simulator')
                }
            }
        }

        stage('Docker Login') {
            steps {
                script {
                    docker.withRegistry('https://index.docker.io/v1/', DOCKER_CREDENTIALS) {
                        echo "Logged in to Docker Hub"
                    }
                }
            }
        }

        stage('Push Docker Images') {
            steps {
                script {
                    docker.withRegistry('https://index.docker.io/v1/', DOCKER_CREDENTIALS) {
                        docker.image(ML_IMAGE).push()
                        docker.image(PREPROCESS_IMAGE).push()
                        docker.image(CAPTURE_IMAGE).push()
                        docker.image(FRONTEND_IMAGE).push()
                        docker.image(SIMULATOR_IMAGE).push()
                    }
                }
            }
        }

        stage('Cleanup Docker Images') {
            steps {
                script {
                    sh 'docker image prune -f'
                }
            }
        }

        stage('Deploy to Kubernetes') {
            steps {
                withEnv(["KUBECONFIG=${env.KUBECONFIG}"]) {
                    script {
                        sh '''
                            sed -i "s|image: ml-service|image: ${ML_IMAGE}|g" kubernetes/ml-deployment.yaml
                            sed -i "s|image: preprocessing-service|image: ${PREPROCESS_IMAGE}|g" kubernetes/preprocessing-deployment.yaml
                            sed -i "s|image: capture-service|image: ${CAPTURE_IMAGE}|g" kubernetes/capture-deployment.yaml
                            sed -i "s|image: frontend-service|image: ${FRONTEND_IMAGE}|g" kubernetes/frontend-deployment.yaml
                            sed -i "s|image: simulator-service|image: ${SIMULATOR_IMAGE}|g" kubernetes/simulator-deployment.yaml
                        '''
                        sh '''
                            kubectl config current-context
                            kubectl get nodes
                            kubectl apply -f kubernetes/
                        '''
                    }
                }
            }
        }

        stage('Ingress Setup') {
            steps {
                withEnv(["KUBECONFIG=${env.KUBECONFIG}"]) {
                    dir('ansible') {
                        sh 'ansible-galaxy collection install kubernetes.core'
                        sh '''
                        ansible-playbook ingress-setup.yml
                        '''
                    }
                }
            }
        }


        stage('Print Access URLs') {
            steps {
                withEnv(["KUBECONFIG=${env.KUBECONFIG}"]) {
                    script {
                        sh '''
                        echo "Access Info:"
                        echo "========================="
                        echo "Frontend: $(minikube service frontend-service --url)"
                        echo "Prometheus: $(minikube service prometheus-service --url)"
                        echo "Grafana: $(minikube service grafana-service --url)"
                        echo "========================="
                        '''
                    }
                }
            }
        }


        // stage('Deploy ELK Stack') {
        //     steps {
        //         withEnv(["KUBECONFIG=${env.KUBECONFIG}"]) {
        //             script {
        //                 sh '''
        //                 kubectl apply -f kubernetes/elk/
        //                 '''
        //             }
        //         }
        //     }
        // }

        // stage('Deploy Prometheus and Grafana') {
        //     steps {
        //         withEnv(["KUBECONFIG=${env.KUBECONFIG}"]) {
        //             script {
        //                 sh '''
        //                 kubectl apply -f kubernetes/monitoring/
        //                 '''
        //             }
        //         }
        //     }
        // }

    }

    post {
        success {
            echo "Deployment completed successfully!"
        }
        failure {
            echo "Something went wrong. Check the logs."
        }
    }
}
