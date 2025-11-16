from flask import Flask, render_template, request, send_file, jsonify
import tempfile
import os
import logging
from piawg import piawg
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

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
        regions = list(pia.server_list.keys())
        regions.sort()
        logger.info(f"Retrieved {len(regions)} available regions")
        return jsonify(regions)
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

        # Get token
        if not pia.get_token(username, password):
            logger.warning(f"Authentication failed for user: {username}")
            return jsonify({'error': 'Invalid credentials or authentication failed'}), 401

        # Add key to server
        status, response = pia.addkey()
        if not status:
            logger.error(f"Failed to register key with server for region: {region}")
            return jsonify({'error': 'Failed to register key with server'}), 500
        
        # Generate dynamic filename based on region
        sanitized_region = sanitize_region_for_filename(region)
        tunnel_name = f'PIA-{sanitized_region}'

        # Generate config content
        config_content = f"""[Interface]
Address = {pia.connection['peer_ip']}
PrivateKey = {pia.privatekey}
DNS = {pia.connection['dns_servers'][0]},{pia.connection['dns_servers'][1]}

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