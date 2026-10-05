# 보안 / Security / 安全 / Seguridad

## 한국어

이 프로그램은 커널 권한으로 프로세스 메모리를 읽고 변경합니다. 현재 FastAPI 서버에는 인증 계층이 없으며, 드라이버 장치의 접근 정책은 시스템 배포 설정에 따라 확인해야 합니다. 기본 `127.0.0.1` 바인딩을 유지하고 소유하거나 명시적으로 허가받은 테스트 대상에 사용하세요. 단순 빌드 성공은 공개 서비스 또는 제품 배포의 보안 검증을 의미하지 않습니다.

발견한 문제는 [GitHub 보안 탭](https://github.com/lastime1650/Kernel_Based_ProcessMemory_Editor/security)에서 비공개 보고가 제공되면 그 경로로 보고하세요. 비공개 경로가 없다면 공개 이슈에는 세부 공격 절차·덤프·민감 데이터를 넣지 말고 비공개 연락 경로를 요청하세요. 고정된 보안 연락처·지원 SLA·검증된 지원 OS 목록은 아직 없습니다. 보고에는 커밋/드라이버 버전, OS 빌드, 영향과 민감 정보를 제거한 최소 재현을 포함하세요. 인증서·토큰·실제 메모리·개인 PDB를 첨부하지 마세요.

## English

The program reads and changes process memory with kernel privileges. The FastAPI server has no authentication layer. Review device access policy for your deployment and keep the default `127.0.0.1` binding. Use owned or explicitly authorized test targets. Successful compilation does not constitute a security review for public hosting or product deployment.

Use private reporting in the [GitHub Security tab](https://github.com/lastime1650/Kernel_Based_ProcessMemory_Editor/security) if available. Otherwise request a private contact through a sanitized public issue without exploit details, dumps or sensitive data. No dedicated security contact, support SLA or validated OS support matrix is currently published. Include commit/driver version, OS build, impact and a sanitized minimal reproduction. Do not attach credentials, certificates, real memory or private PDBs.

## 简体中文

程序使用内核权限读写进程内存。FastAPI 服务器没有认证层；部署时需核对设备访问策略，并保持默认 `127.0.0.1` 绑定。仅用于拥有或明确获准的测试目标。构建成功不等于公开托管或产品部署的安全审查。

若 [GitHub 安全页面](https://github.com/lastime1650/Kernel_Based_ProcessMemory_Editor/security)提供私密报告，请使用该入口；否则通过去敏的公开问题请求私密联系方式，不发布攻击步骤、转储或敏感数据。目前没有专用安全联系人、支持 SLA 或已验证 OS 支持矩阵。报告应含提交/驱动版本、OS 构建、影响及去敏最小复现。不要附凭据、证书、真实内存或私人 PDB。

## Español

El programa lee y modifica memoria con privilegios del kernel. FastAPI no tiene autenticación. Revise la política de acceso al dispositivo para su despliegue y mantenga `127.0.0.1`. Use destinos de prueba propios o expresamente autorizados. Compilar correctamente no equivale a una revisión de seguridad para alojamiento público o distribución como producto.

Use informes privados en la [pestaña Security](https://github.com/lastime1650/Kernel_Based_ProcessMemory_Editor/security) si están disponibles. En caso contrario solicite contacto privado mediante una incidencia pública sin detalles de explotación, volcados ni datos sensibles. No hay contacto de seguridad dedicado, SLA ni matriz OS validada publicados. Indique versión/commit, compilación OS, impacto y reproducción mínima anonimizada. No adjunte credenciales, certificados, memoria real ni PDB privados.
