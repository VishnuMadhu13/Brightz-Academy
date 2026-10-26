pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        disableConcurrentBuilds()
    }

    parameters {
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
        DAST_URL      = 'http://brightmindz_frontend:80'    // container name on the compose network
        // Try GitHub registry first, then the AWS public mirror
        TRIVY_DB_REPOSITORY = 'ghcr.io/aquasecurity/trivy-db,public.ecr.aws/aquasecurity/trivy-db'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                sh '''
                    mkdir -p "${REPORTS}"
                    cat > generate_scan_report.py <<'PYREPORT'
import html, json, os
from pathlib import Path
from datetime import datetime, timezone

reports = Path(os.environ.get("REPORTS", "reports"))
reports.mkdir(parents=True, exist_ok=True)
output = reports / "devsecops-scan-report.html"
scans = {
    "bandit-report.json": "Bandit — Python SAST",
    "semgrep-report.json": "Semgrep — SAST",
    "pip-audit.json": "pip-audit — Python dependencies",
    "npm-audit.json": "npm audit — frontend dependencies",
    "trivy-fs.json": "Trivy filesystem scan",
    "zap-report.json": "OWASP ZAP — DAST",
}
for p in sorted(reports.glob("trivy-image-*.json")):
    scans[p.name] = "Trivy image scan: " + p.name

def walk(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v)

sections, rows = [], []
for filename, title in scans.items():
    path = reports / filename
    if not path.exists():
        sections.append("<section><h2>" + html.escape(title) + "</h2><p class='missing'>Report missing; check the Jenkins stage log. Missing does not mean passed.</p></section>")
        rows.append((title, "Missing", "No report generated"))
        continue
    try:
        data = json.loads(path.read_text(errors="replace"))
        counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        for item in walk(data):
            sev = item.get("Severity", item.get("severity", item.get("risk", "")))
            if isinstance(sev, str) and sev.upper() in counts:
                counts[sev.upper()] += 1
        severity = ", ".join(f"{k}: {v}" for k, v in counts.items() if v) or "No standard severity fields recognized"
        raw = html.escape(json.dumps(data, indent=2, ensure_ascii=False))
        sections.append("<section><h2>" + html.escape(title) + "</h2><p><b>Recognized severity counts:</b> " + html.escape(severity) + "</p><details><summary>View complete JSON results</summary><pre>" + raw + "</pre></details></section>")
        rows.append((title, "Available", severity))
    except Exception as exc:
        sections.append("<section><h2>" + html.escape(title) + "</h2><p class='error'>Could not parse JSON: " + html.escape(str(exc)) + "</p></section>")
        rows.append((title, "Parse error", str(exc)))

for filename, title in (("bandit-report.html", "Bandit HTML detail"), ("pip-audit.md", "pip-audit Markdown detail"), ("zap-report.html", "OWASP ZAP HTML detail")):
    path = reports / filename
    if path.exists():
        sections.append("<section><h2>" + html.escape(title) + "</h2><details><summary>View detail output</summary><pre>" + html.escape(path.read_text(errors="replace")) + "</pre></details></section>")

table = "".join("<tr><td>" + html.escape(n) + "</td><td>" + html.escape(s) + "</td><td>" + html.escape(d) + "</td></tr>" for n, s, d in rows)
stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
css = "body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#f4f6f8;color:#17202a}header{background:#14243a;color:white;padding:26px}main{max-width:1100px;margin:24px auto;padding:0 18px}section,.summary{background:white;border:1px solid #dce2e8;border-radius:10px;padding:18px;margin:16px 0;overflow-wrap:anywhere}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #e3e7eb;padding:9px;text-align:left;vertical-align:top}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:650px;overflow:auto;background:#f6f8fa;padding:14px;border-radius:6px;font-size:12px}summary{cursor:pointer;font-weight:600}.missing,.error{color:#a12622}"
document = ("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Consolidated DevSecOps Scan Report</title><style>" + css + "</style></head><body>"
    "<header><h1>Consolidated DevSecOps Scan Report</h1><div>Project: Bright Mindz Academy</div><div>Generated: " + stamp + "</div></header><main>"
    "<div class='summary'><h2>Scan summary</h2><p>All available scan JSON outputs are included below. Missing outputs are marked and must not be interpreted as passing scans.</p>"
    "<table><thead><tr><th>Scanner</th><th>Status</th><th>Recognized severity summary</th></tr></thead><tbody>" + table + "</tbody></table></div>"
    + "".join(sections) + "</main></body></html>")
output.write_text(document)
print("Generated " + str(output))
PYREPORT
                '''
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
                        python manage.py test --noinput
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
                // A failed DAST marks the build UNSTABLE but never blocks the report archiving
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        [ -f .env ] || cp .env.example .env

                        # Start db + backend + frontend. The frontend image has its own nginx and
                        # config baked in, so no host bind mounts are needed (Jenkins runs in a
                        # container, so bind-mount paths would not exist on the Docker host).
                        docker compose up -d db backend frontend

                        echo "Waiting for app at ${DAST_URL} ..."
                        READY=no
                        for i in $(seq 1 24); do
                            CODE=$(docker run --rm --network ${DAST_NET} curlimages/curl -s -o /dev/null -w '%{http_code}' ${DAST_URL} || true)
                            echo "attempt $i: HTTP $CODE"
                            if [ "$CODE" != "000" ] && [ -n "$CODE" ]; then READY=yes; break; fi
                            sleep 5
                        done
                        docker compose ps

                        echo "=================== backend logs (last 80 lines) ==================="
                        docker logs --tail 80 brightmindz_backend 2>&1 || true

                        if [ "$READY" != "yes" ]; then
                            echo "App did not come up. Container logs follow:"
                            for C in brightmindz_backend brightmindz_frontend brightmindz_db; do
                                echo "=================== $C ==================="
                                docker logs --tail 80 $C 2>&1 || true
                            done
                            exit 1
                        fi

                        # ZAP needs /zap/wrk mounted: use a named volume (no host path), then copy reports out
                        docker rm -f zap-scan >/dev/null 2>&1 || true
                        docker volume rm -f zap-wrk >/dev/null 2>&1 || true
                        docker volume create zap-wrk
                        docker run --rm -v zap-wrk:/zap/wrk alpine chmod 777 /zap/wrk
                        docker run --name zap-scan --network ${DAST_NET} -v zap-wrk:/zap/wrk \
                            ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                            -t ${DAST_URL} -r zap-report.html -J zap-report.json -I || true
                        docker cp zap-scan:/zap/wrk/. ${REPORTS}/ || true
                        docker rm -f zap-scan || true
                        docker volume rm -f zap-wrk || true

                        STATE=$(docker inspect -f '{{.State.Status}}' brightmindz_backend 2>/dev/null || echo missing)
                        if [ "$STATE" != "running" ]; then
                            echo "WARNING: backend is '$STATE' - only the frontend was scanned, the API was not tested"
                            exit 1
                        fi
                    '''
                }
            }
            post {
                always {
                    sh 'docker compose down -v || true'
                }
            }
        }

        stage('Generate Consolidated Scan Report') {
            steps {
                sh 'REPORTS="${REPORTS}" python3 generate_scan_report.py && test -s "${REPORTS}/devsecops-scan-report.html"'
            }
        }
    }

    post {
        always {
            sh '''
                if [ -f generate_scan_report.py ]; then
                    REPORTS="${REPORTS}" python3 generate_scan_report.py || echo "WARNING: consolidated report generation failed"
                fi
            '''
            archiveArtifacts artifacts: 'reports/devsecops-scan-report.html', allowEmptyArchive: true, fingerprint: true
            publishHTML(target: [
                reportDir: 'reports', reportFiles: 'devsecops-scan-report.html',
                reportName: 'Consolidated DevSecOps Scan Report', allowMissing: true,
                keepAll: true, alwaysLinkToLastBuild: true
            ])
        }
        success { echo 'Pipeline finished: all scans completed.' }
        failure { echo 'Pipeline failed - check the stage logs and reports/ artifacts.' }
    }
}