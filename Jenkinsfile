pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                git 'https://github.com/your-username/intrusion-detector.git'
            }
        }

        stage('Checkout') {
            steps {
                sh 'python3 model.py' 
                // will generate model.joblib file
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
