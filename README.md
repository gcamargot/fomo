# FOMO Smart Contract Extractor & Security Analysis Suite

Herramienta modular en Python para extraer, descargar y auditar contratos inteligentes con los que una wallet ha interactuado, cubriendo tanto ecosistemas **EVM** (Base, Ethereum, Arbitrum, Optimism, Polygon, BSC) como **Solana**.

Diseñado para construir datasets de contratos on-chain y realizar análisis estático de vulnerabilidades para investigación académica y auditoría de seguridad.

---

## 🛠️ Componentes y Entorno Instalado

Los siguientes componentes ya han sido instalados y configurados en tu entorno:

- **Python User Toolchain**: `requests`, `rich`, `web3`, `tqdm`, `slither-analyzer`, `solc-select`, `crytic-compile`.
- **Compilador Solidity**: `solc 0.8.20` instalado y administrado vía `solc-select`.
- **Foundry Toolkit**: `cast`, `forge`, `anvil`, `chisel` (`~/.foundry/bin`).
- **Solana CLI**: `solana`, `solana-keygen` (`~/.local/share/solana/install/active_release/bin`).
- **Configuración de PATH**: Configurado en `~/.bashrc_fomo`.

Para cargar las variables de entorno en cualquier sesión:
```bash
source ~/.bashrc_fomo
```

---

## 🚀 Uso Rápido

### 1. Extraer contratos de una Wallet EVM (Base por defecto)
Analiza el historial de transacciones y transferencias ERC-20 para descargar automáticamente todos los contratos verificados, ABIs y detectar proxies/implementaciones:
```bash
python3 contract_extractor.py --wallet 0x5D06A812a8d5F301fDb4101E8F39eA73be39eEE4 --chain base
```

### 2. Descargar un contrato específico y auditarlo automáticamente
Descarga el código fuente de un contrato y ejecuta **Slither** para generar un informe de vulnerabilidades (`SECURITY_REPORT.md`):
```bash
python3 contract_extractor.py --contract 0x2626664c2603336E57B271c5C0b26F421741e481 --chain base --auto-scan
```

### 3. Extraer programas y tokens de una Wallet de Solana
Analiza las firmas y transacciones recientes de la wallet para identificar programas ejecutados (Raydium, Pump.fun, Jupiter, etc.) y tokens SPL:
```bash
python3 contract_extractor.py --solana-wallet 321v1oGkFAHnz89w2WL9YKj86PqHHtB48bvrap84sEMP
```

### 4. Volcar el binario ELF (.so) de un programa de Solana
```bash
python3 contract_extractor.py --solana-program 675kPX9Mtx55nit54vq3eThNuH47TXJkzF6fU83osv24
```

### 5. Filtrar descargas por Categoría de Contrato
Permite descargar únicamente contratos de una categoría específica (ej. `ERC20_TOKEN`, `DEX_ROUTER_AGGREGATOR`, `PROXY_FACTORY`, `LENDING_BORROWING`, `ERC4626_VAULT`, `SMART_WALLET_ACCOUNT_ABSTRACTION`):
```bash
python3 contract_extractor.py --wallet 0x... --chain base --category dex_router_aggregator
```

### 6. Generar Métricas y Estadísticas del Dataset para el Paper
Calcula la distribución por tipo de contrato, redes, versiones de compilador y realiza una tabulación cruzada de vulnerabilidades por categoría:
```bash
python3 contract_extractor.py --metrics
```
Genera automáticamente:
- `DATASET_METRICS.md`: Tablas formateadas listas para incluir en el paper.
- `DATASET_METRICS.json`: Datos estructurados para scripts de análisis cuantitativo o gráficas.

### 7. Ejecutar análisis estático (Slither) sobre cualquier carpeta de código descargado
```bash
python3 contract_extractor.py --scan ./contracts/base/0x2626664c2603336e57b271c5c0b26f421741e481/src
```

---

## 📁 Estructura del Dataset Generado

Cada contrato descargado se almacena de forma estructurada en `./contracts/`:

```
contracts/
├── base/
│   └── 0x2626664c2603336e57b271c5c0b26f421741e481/
│       ├── abi.json                  # Interfaz binaria de aplicación (ABI)
│       ├── metadata.json             # Versión de compilador, optimización, proxy info
│       ├── runtime_bytecode.bin      # Bytecode desplegado
│       ├── SECURITY_REPORT.md        # Informe de vulnerabilidades generado por Slither
│       └── src/                      # Código fuente Solidity organizado por directorios
└── solana/
    └── CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK/
        ├── metadata.json
        └── CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK.so  # Binario eBPF/ELF (si ejecutable)
```

---

## 🔑 Claves de API de Exploradores (Opcional)

Por defecto, la herramienta utiliza endpoints abiertos de **Blockscout v2 REST API** y **Sourcify**, los cuales funcionan inmediatamente **sin necesidad de API keys**.

Si deseas usar Etherscan/Basescan oficiales con cuotas ampliadas, puedes exportar tus claves en `~/.bashrc_fomo`:
```bash
export BASESCAN_API_KEY="TU_API_KEY"
export ETHERSCAN_API_KEY="TU_API_KEY"
```
