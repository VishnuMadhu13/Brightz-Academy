pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        disableConcurrentBuilds()
    }

    parameters {
        string(name: 'DAST_TARGET', defaultValue: 'http://brightmindz_nginx:80',
               description: 'Nginx container URL on the compose network, used by the ZAP scan')
        booleanParam(name: 'FAIL_ON_HIGH', defaultValue: false,
               description: 'Fail the build on HIGH/CRITICAL Trivy findings')
    }

    environment {
        PROJECT_KEY   = 'brightmindz-academy'
        SONAR_SERVER  = 'sonarqube'
        SCANNER_TOOL  = 'sonar-scanner'
        TRIVY_VERSION = '0.72.0'
        REPORTS       = 'reports'
        VENV          = "${WORKSPACE}/.venv"
        TRIVY_BIN     = "${WORKSPACE}/bin"
        DAST_NET      = 'brightz-academy_brightmindz_net'   // <project>_<network> from docker compose
        // Try GitHub registry first, then the AWS public mirror
        TRIVY_DB_REPOSITORY = 'ghcr.io/aquasecurity/trivy-db,public.ecr.aws/aquasecurity/trivy-db'
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

        stage('Install Trivy') {
            steps {
                sh '''
                    mkdir -p ${TRIVY_BIN}
                    if [ ! -x ${TRIVY_BIN}/trivy ]; then
                        URL=https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz
                        echo "Downloading $URL"
                        if curl -fSL --retry 3 -o /tmp/trivy.tgz "$URL" && tar -xzf /tmp/trivy.tgz -C ${TRIVY_BIN} trivy; then
                            echo "Trivy installed from release tarball"
                        else
                            echo "Release download failed, trying the install script"
                            curl -fSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
                                | sh -s -- -b ${TRIVY_BIN} v${TRIVY_VERSION}
                        fi
                    fi
                    ${TRIVY_BIN}/trivy --version
                '''
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
                        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
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
        }

        stage('Quality Gate') {
            steps {
                script {
                    try {
                        timeout(time: 3, unit: 'MINUTES') {
                            waitForQualityGate abortPipeline: false
                        }
                    } catch (err) {
                        unstable("Quality gate result not received: ${err.getMessage()}")
                    }
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
                            export PATH=${TRIVY_BIN}:$PATH
                            trivy fs --scanners vuln,secret,misconfig \
                                --skip-dirs node_modules,venv,.venv,bin \
                                --severity HIGH,CRITICAL \
                                --format json --output ${REPORTS}/trivy-fs.json .

                            EXIT_CODE=0
                            if [ "$FAIL_ON_HIGH" = "true" ]; then EXIT_CODE=1; fi
                            trivy fs --scanners vuln,secret,misconfig \
                                --skip-dirs node_modules,venv,.venv,bin \
                                --severity HIGH,CRITICAL \
                                --exit-code $EXIT_CODE .
                        '''
                    }
                }
            }
        }

        stage('Docker Build') {
            steps {
                sh '''
                    [ -f .env ] || cp .env.example .env
                    docker compose build
                '''
            }
        }

        stage('Image Scan (Trivy)') {
            steps {
                sh '''
                    export PATH=${TRIVY_BIN}:$PATH
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

                    # Jenkins runs in a container, so host bind mounts (./docker/nginx/nginx.conf)
                    # would point at paths that do not exist on the Docker host.
                    # Drop the nginx bind mounts and copy the config into the container instead.
                    cat > docker-compose.dast.yml <<'YML'
services:
  nginx:
    volumes: !reset []
    ports: !reset []
YML
                    COMPOSE="docker compose -f docker-compose.yml -f docker-compose.dast.yml"

                    $COMPOSE up -d --no-start
                    docker cp docker/nginx/nginx.conf brightmindz_nginx:/etc/nginx/conf.d/default.conf
                    $COMPOSE up -d

                    echo "Waiting for app at ${DAST_TARGET} ..."
                    READY=no
                    for i in $(seq 1 30); do
                        if docker run --rm --network ${DAST_NET} curlimages/curl -s -o /dev/null ${DAST_TARGET}; then
                            READY=yes; break
                        fi
                        sleep 5
                    done
                    echo "App ready: $READY"
                    $COMPOSE ps

                    # No bind mount for ZAP output: run, then copy the reports out
                    docker rm -f zap-scan >/dev/null 2>&1 || true
                    docker run --name zap-scan --network ${DAST_NET} \
                        ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                        -t ${DAST_TARGET} -r zap-report.html -J zap-report.json -I || true
                    docker cp zap-scan:/zap/wrk/. ${REPORTS}/ || true
                    docker rm -f zap-scan || true
                '''
            }
            post {
                always {
                    sh 'docker compose -f docker-compose.yml -f docker-compose.dast.yml down -v || true'
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