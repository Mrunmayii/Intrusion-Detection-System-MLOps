pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                git 'https://github.com/Mrunmayii/Intrusion-Detection-System-MLOps.git'
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
