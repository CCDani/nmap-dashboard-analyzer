import xml.etree.ElementTree as ET

def get_cvss_rating_and_color(score_str):
    """
    Convierte una puntuación CVSS en un Nivel y un Color.
    Paleta: Rojo, Naranja, Violeta, Gris
    """
    try:
        score = float(score_str)
        if 9.0 <= score <= 10.0:
            return "Critical", (217, 83, 79)  # Rojo
        elif 7.0 <= score <= 8.9:
            return "High", (240, 173, 78)      # Naranja
        elif 4.0 <= score <= 6.9:
            return "Medium", (182, 109, 255)  # Violeta
        elif 0.1 <= score <= 3.9:
            return "Low", (119, 119, 119)      # Gris
        else: # Puntuación 0.0
             return "None", (200, 200, 200)
    except (ValueError, TypeError):
        return "Unknown", (150, 150, 150) # Gris para Desconocido

def get_info_vuln(node, port="unknown", service="unknown"):
    """
    Extrae la información de una vulnerabilidad desde un nodo <script>.
    """
    vuln_cve = []
    vulnerabilities = []

    elem = node.find("table") 
    if elem is None:
        return [] 

    # --- Extraer CVEs ---
    cves_table = elem.find(".//table[@key='ids']")
    if cves_table is not None:
        for cve in cves_table.findall('elem'):
            vuln_cve.append(cve.text.split(':')[-1])

    # --- Extraer CVSS ---
    cvss_node = elem.find(".//elem[@key='cvss']")
    cvss_score = cvss_node.text if cvss_node is not None else 'N/A'

    # --- Extraer otros datos ---
    title_node = elem.find(".//elem[@key='title']")
    state_node = elem.find(".//elem[@key='state']")
    
    # --- CAMPOS PARA EXCEL ---
    desc_node = elem.find(".//table[@key='description']/elem")
    description = desc_node.text if desc_node is not None else "N/A"
    
    disc_date_node = elem.find(".//elem[@key='disclosure']")
    disclosure_date = disc_date_node.text if disc_date_node is not None else 'unknown'
    
    references = []
    refs_table = elem.find(".//table[@key='refs']")
    if refs_table is not None:
        references = [e.text for e in refs_table.findall('elem') if e.text]
    
    if title_node is None or state_node is None:
        return [] 
    
    vulnerabilities.append({
        'port': port,
        'service': service,
        'name': title_node.text,
        'state': state_node.text,
        'cve': vuln_cve,
        'cvss': cvss_score,
        'description': description,
        'disclosure_date': disclosure_date,
        'references': references
    })

    return vulnerabilities

def extract_host_info(host):
    """
    Extrae IP, Puertos, Vulnerabilidades y SO de un nodo <host>.
    """
    ip = host.find('address').attrib['addr']
    ports = []
    vulnerabilities = []

    # --- Extraer Puertos y Vulnerabilidades por puerto ---
    for port in host.find('ports').findall('port'):
        if "open" == port.find('state').attrib.get('state'):          
            port_id = port.attrib['portid']
            service_node = port.find('service')
            
            service = service_node.attrib.get('name', 'unknown') if service_node is not None else 'unknown'
            # Extraer Product y Version
            product = service_node.attrib.get('product', '') if service_node is not None else ''
            version = service_node.attrib.get('version', '') if service_node is not None else ''

            # Almacenamos 4 elementos: (port_id, service, product, version)
            ports.append((port_id, service, product, version))

            # Cadena rica para pasar a la funcion de vulnerabilidades
            rich_service_display = service
            if product:
                rich_service_display += f" ({product}"
                if version:
                    rich_service_display += f" {version})"
                else:
                    rich_service_display += ")"
            
            for script in port.findall('script'):
                if 'vulnerable' in script.attrib['output'].lower() or 'vulners' in script.attrib['id']:
                    vulnerabilities.extend(get_info_vuln(script, port_id, rich_service_display))
                    
    # --- Extraer SO ---
    os_match = host.find(".//osmatch")
    os_name = os_match.attrib.get('name', 'Desconocido') if os_match is not None else 'Desconocido'

    return ip, os_name, ports, vulnerabilities

def parse_nmap_xml(xml_file):
    """
    Función principal que analiza todo el XML y devuelve datos estructurados.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()

    nmap_command = root.attrib.get('args', 'Comando no encontrado')

    hosts_data = [] 
    os_families = {}
    all_service_names = set() 
    all_ports_ids = set()
    total_open_ports = 0
    total_running_services = 0
    
    cve_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0, "Unknown": 0}

    for host in root.findall('host'):
        ip, os_name, ports, vulnerabilities = extract_host_info(host)
        
        os_families[os_name] = os_families.get(os_name, 0) + 1
        
        total_open_ports += len(ports)
        total_running_services += len(ports) 

        max_cvss_score = 0.0
        for vuln in vulnerabilities:
            rating, color = get_cvss_rating_and_color(vuln['cvss'])
            cve_counts[rating] += 1
            
            try:
                max_cvss_score = max(max_cvss_score, float(vuln['cvss']))
            except (ValueError, TypeError):
                continue
        
        for port_id, service_name, product, version in ports:
            all_ports_ids.add(port_id)
            all_service_names.add(service_name)

        hosts_data.append({
            'ip': ip,
            'os': os_name,
            'ports': ports,
            'vulnerabilities': vulnerabilities,
            'max_cvss': max_cvss_score
        })

    summary_data = {
        "nmap_command": nmap_command,
        "scanned_assets": len(hosts_data),
        "services": total_running_services, 
        "ports": total_open_ports,
        "unique_services": all_service_names,
        "cve_counts": cve_counts,
        "os_families": os_families # <-- ¡ESTA ES LA LÍNEA QUE FALTABA!
    }

    return summary_data, hosts_data
