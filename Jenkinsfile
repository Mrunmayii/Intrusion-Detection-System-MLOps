pipeline {
    agent any

    environment {
        GIT_CREDENTIALS_ID = 'github-creds' 
    }

    stages {
        stage('Checkout') {
            steps {
                git url: 'https://github.com/Mrunmayii/Intrusion-Detection-System-MLOps.git',
                credentialsId: GIT_CREDENTIALS_ID,
                branch: 'main'
            }
        }

        stage('Train model') {
            steps {
                sh 'python3 model.py' 
            }
        }

        stage('Build & Deploy') {
            steps {
                sh 'docker-compose down'
                sh 'docker-compose up --build -d'
            }
        }
    }

    post {
        always {
            sh 'docker-compose ps'
        }
    }
}
