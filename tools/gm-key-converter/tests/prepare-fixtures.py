"""获取固定版本 BC 依赖，仅生成合成测试材料，不读取用户证书和私钥。"""
import hashlib
import os
from pathlib import Path
import subprocess
import urllib.request

root = Path(__file__).resolve().parents[1]
fixtures = root / 'build' / 'fixtures'
fixtures.mkdir(parents=True, exist_ok=True, mode=0o700)
libs = root / 'build' / 'bc'
libs.mkdir(exist_ok=True)
HASHES = {'bcprov-jdk18on': 'e8ad209f8c58d291a37ca9750e9e9fac60596956c983e49dd8282381dd8b3249', 'bcpkix-jdk18on': '4f4ba6a92617ea19dc183f0fa5db492eee426fdde2a0a2d6c94777ffd1af6413', 'bcutil-jdk18on': '22eca687f7955411f456af33e6ea8e68fc73cd80cb8b32aa5f7a8b1827d7c678'}
jars = []
for artifact, expected in HASHES.items():
    name = f'{artifact}-1.80.jar'
    target = libs / name
    cache = Path.home() / '.gradle/caches/modules-2/files-2.1/org.bouncycastle' / artifact / '1.80'
    candidates = [target, *sorted(cache.glob(f'**/{name}'))]
    valid = next((p for p in candidates if p.exists() and hashlib.sha256(p.read_bytes()).hexdigest() == expected), None)
    if valid is None:
        url = f'https://repo.maven.apache.org/maven2/org/bouncycastle/{artifact}/1.80/{name}'
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != expected:
            raise SystemExit(f'{name} 的 SHA-256 校验失败')
        target.write_bytes(data)
        valid = target
    jars.append(valid)
classpath = os.pathsep.join(map(str, jars))
(fixtures / 'classpath.txt').write_text(classpath)
subprocess.run(['java', '--class-path', classpath, str(root / 'tests/GmInterop.java'), 'generate', str(fixtures)], check=True)
