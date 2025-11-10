"""
Command Line Interface for GTP Analyzer

Provides multiple sub-commands for GTP PCAP analysis.
"""

import click
import sys
from colorama import init, Fore, Style
from .gtp_parser import GTPParser
from .teid_tracker import TEIDTracker
from .session_reconstructor import SessionReconstructor
from .report_generator import ReportGenerator

# Initialize colorama for cross-platform colored output
init(autoreset=True)


def print_success(message: str):
    """Print success message in green"""
    click.echo(Fore.GREEN + message + Style.RESET_ALL)


def print_error(message: str):
    """Print error message in red"""
    click.echo(Fore.RED + "Error: " + message + Style.RESET_ALL, err=True)


def print_warning(message: str):
    """Print warning message in yellow"""
    click.echo(Fore.YELLOW + "Warning: " + message + Style.RESET_ALL)


def print_info(message: str):
    """Print info message in cyan"""
    click.echo(Fore.CYAN + message + Style.RESET_ALL)


@click.group()
@click.version_option(version='1.0.0')
def main():
    """
    GTP Analyzer - Comprehensive GTP Wireshark PCAP analysis utility
    
    Analyze GTP (GPRS Tunnelling Protocol) packet captures with support for
    GTPv1 and GTPv2. Track TEIDs, reconstruct sessions, and generate reports.
    """
    pass


@main.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.option('--limit', '-l', default=None, type=int, help='Limit number of packets to display')
@click.option('--message-type', '-m', default=None, type=int, help='Filter by message type')
def parse(pcap_file, limit, message_type):
    """
    Parse and display GTP packets from PCAP file
    
    Example:
        gtp-analyzer parse capture.pcap
        gtp-analyzer parse capture.pcap --limit 20
        gtp-analyzer parse capture.pcap --message-type 16
    """
    try:
        print_info(f"Parsing PCAP file: {pcap_file}")
        parser = GTPParser(pcap_file)
        packets = parser.parse()
        
        if not packets:
            print_warning("No GTP packets found in PCAP file")
            return
        
        print_success(f"Found {len(packets)} GTP packets")
        
        # Apply filters
        if message_type is not None:
            packets = parser.filter_by_message_type(message_type)
            print_info(f"Filtered to {len(packets)} packets with message type {message_type}")
        
        # Apply limit
        if limit:
            packets = packets[:limit]
        
        # Generate and display table
        report_gen = ReportGenerator(parser)
        table = report_gen.generate_packet_table(packets)
        click.echo("\n" + table)
        
    except Exception as e:
        print_error(str(e))
        sys.exit(1)


@main.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.argument('teid', type=int)
@click.option('--export', '-e', default=None, help='Export to file (JSON)')
def teid_track(pcap_file, teid, export):
    """
    Track specific TEID lifecycle and usage
    
    Example:
        gtp-analyzer teid-track capture.pcap 12345
        gtp-analyzer teid-track capture.pcap 12345 --export teid_report.json
    """
    try:
        print_info(f"Tracking TEID {teid} in {pcap_file}")
        
        parser = GTPParser(pcap_file)
        packets = parser.parse()
        
        if not packets:
            print_warning("No GTP packets found in PCAP file")
            return
        
        # Track TEIDs
        tracker = TEIDTracker()
        tracker.track_packets(packets)
        
        lifecycle = tracker.get_teid_lifecycle(teid)
        
        if not lifecycle:
            print_error(f"TEID {teid} not found in capture")
            print_info(f"Available TEIDs: {', '.join(map(str, tracker.get_all_teids()[:20]))}")
            sys.exit(1)
        
        # Generate report
        report_gen = ReportGenerator(parser)
        report = report_gen.generate_teid_lifecycle_report(teid, tracker)
        click.echo(report)
        
        # Export if requested
        if export:
            import json
            with open(export, 'w') as f:
                json.dump(lifecycle.to_dict(), f, indent=2)
            print_success(f"Report exported to {export}")
        
    except Exception as e:
        print_error(str(e))
        sys.exit(1)


@main.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.option('--session-id', '-s', default=None, help='Show specific session')
@click.option('--export', '-e', default=None, help='Export to file (JSON)')
def session(pcap_file, session_id, export):
    """
    Reconstruct and display GTP sessions
    
    Example:
        gtp-analyzer session capture.pcap
        gtp-analyzer session capture.pcap --session-id Session-1
        gtp-analyzer session capture.pcap --export sessions.json
    """
    try:
        print_info(f"Reconstructing sessions from {pcap_file}")
        
        parser = GTPParser(pcap_file)
        packets = parser.parse()
        
        if not packets:
            print_warning("No GTP packets found in PCAP file")
            return
        
        # Reconstruct sessions
        reconstructor = SessionReconstructor()
        sessions = reconstructor.reconstruct_sessions(packets)
        
        print_success(f"Reconstructed {len(sessions)} session(s)")
        
        if session_id:
            # Show specific session
            sess = reconstructor.get_session(session_id)
            if not sess:
                print_error(f"Session {session_id} not found")
                available = [s.session_id for s in sessions[:10]]
                print_info(f"Available sessions: {', '.join(available)}")
                sys.exit(1)
            click.echo(sess.generate_flow_summary())
        else:
            # Show all sessions summary
            for sess in sessions:
                click.echo(sess.generate_flow_summary())
        
        # Export if requested
        if export:
            import json
            summary = reconstructor.get_sessions_summary()
            with open(export, 'w') as f:
                json.dump(summary, f, indent=2)
            print_success(f"Sessions exported to {export}")
        
    except Exception as e:
        print_error(str(e))
        sys.exit(1)


@main.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.option('--teid-summary', '-t', is_flag=True, help='Include TEID summary')
def stats(pcap_file, teid_summary):
    """
    Generate comprehensive statistics from PCAP
    
    Example:
        gtp-analyzer stats capture.pcap
        gtp-analyzer stats capture.pcap --teid-summary
    """
    try:
        print_info(f"Generating statistics for {pcap_file}")
        
        parser = GTPParser(pcap_file)
        packets = parser.parse()
        
        if not packets:
            print_warning("No GTP packets found in PCAP file")
            return
        
        # Generate statistics
        report_gen = ReportGenerator(parser)
        stats_table = report_gen.generate_statistics_table()
        click.echo(stats_table)
        
        # TEID summary if requested
        if teid_summary:
            tracker = TEIDTracker()
            tracker.track_packets(packets)
            
            summary = tracker.generate_summary_report()
            
            click.echo("\n" + "=" * 80)
            click.echo("TEID SUMMARY")
            click.echo("=" * 80)
            click.echo(f"Total TEIDs: {summary['total_teids']}")
            click.echo(f"Active TEIDs: {summary['active_teids']}")
            click.echo(f"Deleted TEIDs: {summary['deleted_teids']}")
            click.echo(f"Total Data Packets: {summary['total_data_packets']}")
            click.echo(f"Total Control Packets: {summary['total_control_packets']}")
            
            click.echo("\n--- TEID Details ---")
            from tabulate import tabulate
            headers = ['TEID', 'Status', 'Packets', 'Data', 'Control', 'Duration(s)']
            rows = []
            for teid_info in summary['teids'][:20]:  # Show first 20
                rows.append([
                    teid_info['teid'],
                    teid_info['status'],
                    teid_info['total_packets'],
                    teid_info['data_packets'],
                    teid_info['control_packets'],
                    f"{teid_info['duration_seconds']:.3f}" if teid_info['duration_seconds'] else 'N/A'
                ])
            click.echo(tabulate(rows, headers=headers, tablefmt='grid'))
            
            if summary['total_teids'] > 20:
                click.echo(f"\n(Showing first 20 of {summary['total_teids']} TEIDs)")
        
    except Exception as e:
        print_error(str(e))
        sys.exit(1)


@main.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.argument('format', type=click.Choice(['json', 'csv'], case_sensitive=False))
@click.argument('output_file', type=click.Path())
@click.option('--include-packets/--no-packets', default=True, help='Include packet details in JSON export')
def export(pcap_file, format, output_file, include_packets):
    """
    Export analysis results to JSON or CSV
    
    Example:
        gtp-analyzer export capture.pcap json output.json
        gtp-analyzer export capture.pcap csv output.csv
        gtp-analyzer export capture.pcap json output.json --no-packets
    """
    try:
        print_info(f"Exporting {pcap_file} to {format.upper()} format")
        
        parser = GTPParser(pcap_file)
        packets = parser.parse()
        
        if not packets:
            print_warning("No GTP packets found in PCAP file")
            return
        
        report_gen = ReportGenerator(parser)
        
        if format.lower() == 'json':
            report_gen.export_to_json(output_file, include_packets=include_packets)
        elif format.lower() == 'csv':
            report_gen.export_to_csv(output_file)
        
        print_success(f"Successfully exported to {output_file}")
        
    except Exception as e:
        print_error(str(e))
        sys.exit(1)


@main.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.option('--teid', '-t', type=int, help='Filter by TEID')
@click.option('--message-type', '-m', type=int, help='Filter by message type')
@click.option('--src-ip', '-s', help='Filter by source IP')
@click.option('--dst-ip', '-d', help='Filter by destination IP')
@click.option('--limit', '-l', default=None, type=int, help='Limit number of packets to display')
def filter(pcap_file, teid, message_type, src_ip, dst_ip, limit):
    """
    Apply filters to GTP packets
    
    Example:
        gtp-analyzer filter capture.pcap --teid 12345
        gtp-analyzer filter capture.pcap --message-type 16
        gtp-analyzer filter capture.pcap --src-ip 192.168.1.1
        gtp-analyzer filter capture.pcap --teid 12345 --limit 10
    """
    try:
        print_info(f"Filtering packets in {pcap_file}")
        
        parser = GTPParser(pcap_file)
        packets = parser.parse()
        
        if not packets:
            print_warning("No GTP packets found in PCAP file")
            return
        
        original_count = len(packets)
        
        # Apply filters
        if teid is not None:
            packets = [p for p in packets if p.teid == teid]
            print_info(f"TEID filter: {len(packets)} packets match TEID {teid}")
        
        if message_type is not None:
            packets = [p for p in packets if p.message_type == message_type]
            print_info(f"Message type filter: {len(packets)} packets match type {message_type}")
        
        if src_ip:
            packets = [p for p in packets if p.src_ip == src_ip]
            print_info(f"Source IP filter: {len(packets)} packets from {src_ip}")
        
        if dst_ip:
            packets = [p for p in packets if p.dst_ip == dst_ip]
            print_info(f"Destination IP filter: {len(packets)} packets to {dst_ip}")
        
        if not packets:
            print_warning("No packets match the specified filters")
            return
        
        print_success(f"Filtered from {original_count} to {len(packets)} packets")
        
        # Apply limit
        if limit:
            packets = packets[:limit]
        
        # Generate and display table
        report_gen = ReportGenerator(parser)
        table = report_gen.generate_packet_table(packets, highlight_teid=teid)
        click.echo("\n" + table)
        
    except Exception as e:
        print_error(str(e))
        sys.exit(1)


if __name__ == '__main__':
    main()
