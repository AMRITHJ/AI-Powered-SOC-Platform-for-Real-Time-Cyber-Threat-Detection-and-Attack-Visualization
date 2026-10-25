# AI-Powered SOC Platform for Real-Time Cyber Threat Detection and Attack Visualization

An intelligent, lightweight Security Operations Center (SOC) research platform designed to integrate real-time network monitoring, machine-learning-based attack classification, anomaly detection, behavioural analysis, and Cyber Threat Intelligence (CTI) into a unified security monitoring environment.

The platform captures network traffic using **Scapy and Npcap**, processes packets into network-flow information, and extracts 41 network-flow features for security analysis. It integrates **Random Forest and BiLSTM** for supervised attack classification, alongside **Isolation Forest** for unsupervised anomaly detection and behavioural rules for identifying suspicious network activity.

To enhance threat investigation, the system integrates external Cyber Threat Intelligence sources, including **AbuseIPDB, VirusTotal, and AlienVault OTX**, where available. Detection results and contextual information are processed through a risk-assessment pipeline before being presented on an interactive dashboard.

Developed using **Python, Flask, Flask-SocketIO, Scikit-learn, PyTorch, SQLite, and modern web visualization technologies**, the platform provides real-time security event monitoring, attack visualization, network topology, device information, detection logs, Telegram notifications, and forensic report generation.

The project is evaluated within an isolated VMware virtual laboratory using controlled cybersecurity experiments, including port scanning, repeated authentication attempts, and high-rate traffic scenarios. Its evaluation combines offline machine-learning metrics with end-to-end testing of the live detection workflow.

### Key Features
- **Real-Time Network Monitoring:** Capture and process network packets using Scapy and Npcap.
- **AI-Based Attack Classification:** Apply Random Forest and BiLSTM models to network-flow features.
- **Anomaly Detection:** Use Isolation Forest to identify potentially unusual network activity.
- **Behavioural Detection:** Identify suspicious patterns such as port scanning, repeated authentication attempts, and high-rate traffic.
- **Cyber Threat Intelligence:** Enrich security events using AbuseIPDB, VirusTotal, and AlienVault OTX integrations.
- **Risk Assessment:** Combine detection outcomes and available threat context to support security-event prioritization.
- **Interactive SOC Dashboard:** Visualize traffic activity, security alerts, devices, network topology, and detection results.
- **Real-Time Notifications:** Deliver security notifications through Telegram.
- **Event Storage and Forensic Reporting:** Store security events in SQLite and support report generation.
- **Controlled Laboratory Evaluation:** Test the integrated platform in an isolated VMware environment.

### Machine Learning Evaluation
- **Random Forest:** 95.92% accuracy and 96.56% weighted F1-score.
- **BiLSTM:** 93.68% accuracy and 93.70% weighted F1-score.
- **Isolation Forest:** Evaluated separately for its anomaly-detection task; its reported metrics are not directly comparable to the supervised classification results.

### Technology Stack
Python · Flask · Flask-SocketIO · Scapy · Npcap · Scikit-learn · PyTorch · Pandas · NumPy · SQLite · HTML · CSS · JavaScript · Leaflet.js · Chart.js · ReportLab · Cowrie · VMware Workstation

### Project Objective
The primary objective is to demonstrate how machine learning, behavioural detection, threat intelligence, risk assessment, and real-time visualization can be integrated into a lightweight SOC research prototype.

**Project Scope:** Academic cybersecurity research and controlled laboratory evaluation. The platform is intended for experimentation, learning, and further development; it is not presented as a replacement for a production enterprise SOC.
