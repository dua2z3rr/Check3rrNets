# Check3rrNets: Port Scanner

**Linguaggi:** Python  
**Framework/Tool:** Scapy, Argparse, Threading  
**Licenza:** MIT  

## Funzionalità
1. Scansione TCP (SYN/Connect)
2. Rilevamento banner dei servizi
3. Supporto multithreading
4. Filtraggio personalizzabile delle porte
5. Esportazione risultati in formato JSON/CSV

## Configurazione
```bash
git clone https://github.com/dua2z3rr/Check3rrNets.git
cd Check3rrNets
```

## Opzioni
```
--target       IP o hostname da scansionare
--ports        Porte specifiche (es: 80,443) o range (es: 1-1000)
--scan-type    Modalità di scansione [syn|connect]
--threads      Numero thread concorrenti (default: 50)
--output       Esporta risultati [json|csv]
--banner       Attiva banner grabbing
```

## Esempio di Output
```plaintext
Porta 80/tcp   OPEN   HTTP/1.1 404 Not Found
Porta 22/tcp   OPEN   SSH-2.0-OpenSSH_8.4p1
Porta 443/tcp  OPEN   HTTP/1.1 200 OK
```

## File Ignorati
Il repository include un `.gitignore` preconfigurato per:
- File compilati Python (`*.pyc`)
- Ambienti virtuali (`venv/`)
- File di configurazione (`.env`)
- Directory di log (`logs/`)

## Licenza
Distribuito sotto licenza MIT. Consultare il file `LICENSE` per i dettagli.
