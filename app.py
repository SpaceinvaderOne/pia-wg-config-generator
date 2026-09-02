from flask import Flask, render_template, request, send_file, jsonify
import tempfile
import os
import logging
from piawg import piawg, PIAError
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Each PIA region carries an ISO country code, used to group the region
# dropdown by continent. Any code not listed here falls into "Other" so a
# newly added country still appears in the list rather than disappearing.
REGION_GROUPS = [
    ('United States', {'US'}),
    ('Europe', {
        'AL', 'AD', 'AT', 'BY', 'BE', 'BA', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE',
        'FI', 'FR', 'DE', 'GR', 'HU', 'IS', 'IE', 'IM', 'IT', 'LV', 'LI', 'LT',
        'LU', 'MK', 'MT', 'MD', 'MC', 'ME', 'NL', 'NO', 'PL', 'PT', 'RO', 'RS',
        'SK', 'SI', 'ES', 'SE', 'CH', 'UA', 'GB', 'XK', 'GI', 'GG', 'JE', 'FO',
    }),
    ('Asia', {
        'AM', 'AZ', 'BH', 'BD', 'BN', 'KH', 'CN', 'GE', 'HK', 'IN', 'ID', 'IL',
        'JP', 'JO', 'KZ', 'KW', 'KG', 'LA', 'LB', 'MO', 'MY', 'MN', 'MM', 'NP',
        'OM', 'PK', 'PH', 'QA', 'SA', 'SG', 'LK', 'SY', 'TW', 'TJ', 'TH', 'TR',
        'AE', 'UZ', 'VN', 'YE', 'IQ', 'IR', 'KR',
    }),
    ('Oceania', {'AU', 'NZ', 'NC', 'PG', 'FJ'}),
    ('North America', {'CA', 'GL'}),
    ('Latin America', {
        'AR', 'BO', 'BR', 'CL', 'CO', 'CR', 'CU', 'DO', 'EC', 'SV', 'GT', 'HN',
        'JM', 'MX', 'NI', 'PA', 'PY', 'PE', 'PR', 'UY', 'VE', 'BS', 'BB', 'BZ',
        'TT', 'GY', 'SR', 'AW',
    }),
    ('Africa', {
        'DZ', 'AO', 'EG', 'GH', 'KE', 'MA', 'MU', 'NG', 'ZA', 'TN', 'UG', 'ZW',
        'SN', 'CI', 'ET',
    }),
]

OTHER_GROUP = 'Other'

def group_regions(server_list):
    """Arrange regions into continent groups for the dropdown.

    Returns a list of groups in display order, each holding its regions sorted
    by name along with whether that region supports port forwarding.
    """
    country_to_group = {
        code: label for label, codes in REGION_GROUPS for code in codes
    }
    grouped = {label: [] for label, _ in REGION_GROUPS}
    grouped[OTHER_GROUP] = []

    for name, region in server_list.items():
        label = country_to_group.get(region.get('country'), OTHER_GROUP)
        grouped[label].append({
            'name': name,
            'port_forward': bool(region.get('port_forward')),
        })

    ordered = [label for label, _ in REGION_GROUPS] + [OTHER_GROUP]
    return [
        {'label': label, 'regions': sorted(grouped[label], key=lambda r: r['name'])}
        for label in ordered if grouped[label]
    ]

def sanitize_region_for_filename(region_name):
    """
    Convert region name to filename-safe format
    Examples:
      "US East" -> "us-east"
      "UK London" -> "uk-london"
      "IT Streaming Optimized" -> "it-streaming-optimized"
    """
    # Convert to lowercase
    name = region_name.lower()

    # Replace spaces with hyphens
    name = name.replace(' ', '-')

    # Remove any remaining non-alphanumeric chars except hyphens
    name = ''.join(c if c.isalnum() or c == '-' else '' for c in name)

    # Remove consecutive hyphens
    name = '-'.join(filter(None, name.split('-')))

    return name

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/regions')
def get_regions():
    """Get available PIA regions for dropdown"""
    try:
        pia = piawg()
        groups = group_regions(pia.server_list)
        logger.info(f"Retrieved {len(pia.server_list)} available regions "
                    f"in {len(groups)} groups")
        return jsonify(groups)
    except PIAError as e:
        logger.error(f"Failed to retrieve regions: {str(e)}")
        return jsonify({'error': str(e)}), 502
    except Exception as e:
        logger.error(f"Failed to retrieve regions: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/generate', methods=['POST'])
def generate_config():
    """Generate and download WireGuard config"""
    temp_file = None
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        region = request.form.get('region')

        if not all([username, password, region]):
            logger.warning("Config generation attempted with missing fields")
            return jsonify({'error': 'All fields are required'}), 400

        # Initialize PIA client
        pia = piawg()

        # Validate region selection
        if region not in pia.server_list:
            logger.warning(f"Invalid region selected: {region}")
            return jsonify({'error': f'Invalid region selected: {region}'}), 400

        logger.info(f"Generating config for region: {region}")

        # Generate keys
        pia.generate_keys()

        # Set region
        pia.set_region(region)

        # Get token. A rejected password is a 401, while PIA being unreachable
        # is a 502, so the user can tell the two apart.
        try:
            authenticated = pia.get_token(username, password)
        except PIAError as e:
            logger.error(f"Could not authenticate with PIA: {str(e)}")
            return jsonify({'error': str(e)}), 502

        if not authenticated:
            logger.warning(f"Authentication failed for user: {username}")
            return jsonify({'error': 'Invalid credentials or authentication failed'}), 401

        # Add key to server
        status, response = pia.addkey()
        if not status:
            logger.error(f"Failed to register key with server for region: {region}")
            return jsonify({'error': f'Failed to register key with any server in {region}'}), 502

        # Generate dynamic filename based on region
        sanitized_region = sanitize_region_for_filename(region)
        tunnel_name = f'PIA-{sanitized_region}'

        # PIA normally returns two resolvers, but use whatever is actually
        # there rather than assuming both are present.
        dns_servers = pia.connection.get('dns_servers') or []
        dns_line = f"DNS = {','.join(dns_servers[:2])}\n" if dns_servers else ""

        # Generate config content
        config_content = f"""[Interface]
Address = {pia.connection['peer_ip']}
PrivateKey = {pia.privatekey}
{dns_line}
# Uncomment the below two PostUp and PreDown routing rules if routing containers through WireGuard container
# PostUp = iptables -t nat -A POSTROUTING -o wg+ -j MASQUERADE
# PreDown = iptables -t nat -D POSTROUTING -o wg+ -j MASQUERADE

# Unraid note: leave the next line commented. Used only for naming the tunnel in Unraid
# {tunnel_name}

[Peer]
PublicKey = {pia.connection['server_key']}
Endpoint = {pia.connection['server_ip']}:1337
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(config_content)
            temp_file = f.name

        logger.info(f"Config generated successfully for region: {region}")

        # Use tunnel_name for filename (already generated above)
        filename = f'{tunnel_name}.conf'

        # Send file
        response = send_file(temp_file,
                           as_attachment=True,
                           download_name=filename,
                           mimetype='text/plain')

        # Clean up temp file after response is sent
        @response.call_on_close
        def cleanup():
            try:
                if temp_file and os.path.exists(temp_file):
                    os.unlink(temp_file)
                    logger.debug(f"Cleaned up temp file: {temp_file}")
            except Exception as e:
                logger.error(f"Failed to cleanup temp file {temp_file}: {str(e)}")

        return response

    except PIAError as e:
        # Raised while reaching PIA itself, so nothing has been written yet.
        logger.error(f"Error generating config: {str(e)}")
        return jsonify({'error': str(e)}), 502

    except Exception as e:
        logger.error(f"Error generating config: {str(e)}")
        # Clean up temp file if it was created
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except Exception:
                pass
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)