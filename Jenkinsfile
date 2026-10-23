pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        disableConcurrentBuilds()
    }

    parameters {
        string(name: 'DAST_TARGET', defaultValue: 'http://localhost:80',
               description: 'URL where docker-compose exposes the app (Nginx) for the ZAP scan')
        booleanParam(name: 'FAIL_ON_HIGH', defaultValue: false,
               description: 'Fail the build on HIGH/CRITICAL dependency or image findings')
    }

    environment {
        PROJECT_KEY   = 'brightmindz-academy'
        SONAR_SERVER  = 'sonarqube'          // Manage Jenkins > System > SonarQube servers (name)
        SCANNER_TOOL  = 'sonar-scanner'      // Manage Jenkins > Tools > SonarQube Scanner (name) (*test comment*)
        IMAGE_NAME    = 'brightmindz-academy'
        TRIVY_VERSION = '0.58.1'
        REPORTS       = 'reports'
        VENV          = "${WORKSPACE}/.venv"
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                sh 'mkdir -p ${REPORTS}'
            }
        }

        stage('Backend: Install & Test') {
            steps {
                dir('backend') {
                    sh '''
                        python3 -m venv ${VENV}
                        . ${VENV}/bin/activate
                        pip install --upgrade pip
                        pip install -r requirements.txt
                        [ -f ../.env ] || cp ../.env.example ../.env
                        python manage.py check
                        python manage.py test --noinput || true
                    '''
                }
            }
        }

        stage('Frontend: Install & Build') {
            steps {
                dir('frontend') {
                    sh '''
                        npm ci
                        npm run build
                    '''
                }
            }
        }

        // ---------------------------- SAST ----------------------------
        stage('SAST') {
            parallel {

                stage('Bandit (Python)') {
                    steps {
                        sh '''
                            . ${VENV}/bin/activate
                            pip install bandit
                            bandit -r backend -x backend/venv,backend/**/tests \
                                -f html -o ${REPORTS}/bandit-report.html || true
                            bandit -r backend -x backend/venv \
                                -f json -o ${REPORTS}/bandit-report.json || true
                        '''
                    }
                }

                stage('Semgrep (Python + TS)') {
                    steps {
                        sh '''
                            . ${VENV}/bin/activate
                            pip install semgrep
                            semgrep scan --config p/django --config p/react --config p/typescript \
                                --config p/owasp-top-ten --exclude node_modules --exclude venv \
                                --json -o ${REPORTS}/semgrep-report.json backend frontend/src || true
                        '''
                    }
                }

                stage('SonarQube') {
                    steps {
                        script {
                            def scannerHome = tool "${SCANNER_TOOL}"
                            withSonarQubeEnv("${SONAR_SERVER}") {
                                sh """
                                    ${scannerHome}/bin/sonar-scanner \
                                      -Dsonar.projectKey=${PROJECT_KEY} \
                                      -Dsonar.projectName='Bright Mindz Academy' \
                                      -Dsonar.sources=backend,frontend/src \
                                      -Dsonar.exclusions=**/node_modules/**,**/venv/**,**/migrations/**,**/dist/** \
                                      -Dsonar.python.version=3.12
                                """
                            }
                        }
                    }
                }
            }
        }

        stage('Quality Gate') {
            steps {
                // Needs a webhook in SonarQube: http://<jenkins>:8080/sonarqube-webhook/
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: false
                }
            }
        }

        // ------------------------ Dependency Scan ----------------------
        stage('Dependency Scan') {
            parallel {

                stage('pip-audit (backend)') {
                    steps {
                        sh '''
                            . ${VENV}/bin/activate
                            pip install pip-audit
                            pip-audit -r backend/requirements.txt \
                                -f json -o ${REPORTS}/pip-audit.json || true
                            pip-audit -r backend/requirements.txt \
                                -f markdown -o ${REPORTS}/pip-audit.md || true
                        '''
                    }
                }

                stage('npm audit (frontend)') {
                    steps {
                        dir('frontend') {
                            sh '''
                                npm audit --json > ../${REPORTS}/npm-audit.json || true
                                npm audit --audit-level=high || true
                            '''
                        }
                    }
                }

                stage('Trivy FS + Secrets') {
                    steps {
                        sh '''
                            if ! command -v trivy >/dev/null 2>&1; then
                                mkdir -p ${WORKSPACE}/bin
                                curl -sSL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
                                    | tar -xz -C ${WORKSPACE}/bin trivy
                            fi
                            export PATH=${WORKSPACE}/bin:$PATH
                            trivy fs --scanners vuln,secret,misconfig \
                                --skip-dirs node_modules,venv,.venv \
                                --severity HIGH,CRITICAL \
                                --format json --output ${REPORTS}/trivy-fs.json .
                            trivy fs --scanners vuln,secret,misconfig \
                                --skip-dirs node_modules,venv,.venv \
                                --severity HIGH,CRITICAL \
                                --exit-code ${FAIL_ON_HIGH == 'true' ? 1 : 0} .
                        '''
                    }
                }
            }
        }

        stage('Docker Build') {
            steps {
                sh '''
                    docker compose build
                '''
            }
        }

        stage('Image Scan (Trivy)') {
            steps {
                sh '''
                    export PATH=${WORKSPACE}/bin:$PATH
                    for IMG in $(docker compose config --images); do
                        NAME=$(echo $IMG | tr '/:' '__')
                        trivy image --severity HIGH,CRITICAL --ignore-unfixed \
                            --format json --output ${REPORTS}/trivy-image-$NAME.json $IMG || true
                    done
                '''
            }
        }

        // ----------------------------- DAST ----------------------------
        stage('DAST (OWASP ZAP)') {
            steps {
                sh '''
                    [ -f .env ] || cp .env.example .env
                    docker compose up -d

                    echo "Waiting for app at ${DAST_TARGET} ..."
                    for i in $(seq 1 30); do
                        curl -s -o /dev/null ${DAST_TARGET} && break
                        sleep 5
                    done

                    mkdir -p ${REPORTS} && chmod 777 ${REPORTS}
                    docker run --rm --network host -v ${WORKSPACE}/${REPORTS}:/zap/wrk:rw \
                        ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                        -t ${DAST_TARGET} \
                        -r zap-report.html -J zap-report.json -I || true
                '''
            }
            post {
                always {
                    sh 'docker compose down -v || true'
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
            publishHTML(target: [
                reportDir: 'reports', reportFiles: 'bandit-report.html,zap-report.html',
                reportName: 'Security Reports', allowMissing: true,
                keepAll: true, alwaysLinkToLastBuild: true
            ])
        }
        success { echo 'Pipeline finished: all scans completed.' }
        failure { echo 'Pipeline failed - check the stage logs and reports/ artifacts.' }
    }
}