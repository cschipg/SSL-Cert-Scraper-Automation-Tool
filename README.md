# SSL-Cert-Scraper-Automation-Tool

#### TLDR: Python script that fetched all DNS records from any company's Cloudflare domains and running nmap scans on open ports within the respective ip addresses to retrieve x509 SSL Certs, serialize it as JSON, and package pertinent info for Prometheus export. Then setting up a FastAPI server exposing an endpoint to populate as HTML the Prometheus-ready data.


### Recent Changes:
- **FastAPI Server Implementation:** Added FastAPI server code to handle requests efficiently.
- **Docker Integration:** Created a Dockerfile to build an Alpine-based Docker image for our application, ensuring a lightweight and secure deployment.
- **Main.py Enhancements:** Implemented caching in the main.py script to improve the reload time of the `/metrics` endpoint. This is expected to enhance performance significantly.
- **Serialization for Certificates:** Added functionality to serialize certificates for JSON export, facilitating easier data handling and storage.
- **Requirements File:** Included a requirements.txt file to guide the Dockerfile on the necessary modules to download, ensuring a smooth build process.

### Major Additions:
- One major addition is the introduction of a caching mechanism in the `main.py` script, which is expected to optimize the performance of the `/metrics` endpoint by reducing load times.
- Enhanced the `main.py` script to allow for the serialization of certificates, streamlining the process of JSON export.

### Next Steps:
- Plan to connect all files to Dockerhub for automated builds and easy distribution.
- Further testing and validation are required to ensure robustness and reliability.

### Areas of Improvement:
- Review caching logic in `main.py` and the serialization process to ensure data integrity and performance efficiency.
- Review Docker setup and configuration to ensure optimal containerization.

