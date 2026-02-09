#!/usr/bin/env python3
"""
Complete SIEM Pipeline Orchestrator
Runs all 5 layers in sequence to generate final correlated UEBA alerts.

Architecture:
    L1: Normalization (normalized.jsonl)
    L2: Enrichment (enriched.jsonl)
    L3: Event Correlation (incidents.jsonl)
    L4: Context & Scoring (scored_incidents.jsonl)
    L5: UEBA (ueba_scores.jsonl) - parallel to L3/L4
    Final: Fusion (correlated_UEBA_alerts.jsonl)

Usage:
    python3 pipeline.py --input raw_logs.jsonl --all
    python3 pipeline.py --input normalized.jsonl --from L2
"""

import argparse
import subprocess
import sys
import os
from datetime import datetime


class PipelineOrchestrator:
    """Orchestrates the complete SIEM pipeline."""
    
    def __init__(self, input_file: str, start_layer: str = "L1"):
        self.input_file = input_file
        self.start_layer = start_layer
        self.results = {}
        
        # Layer definitions
        self.layers = {
            "L1": {
                "name": "Normalization",
                "script": "normalize.py",
                "input": input_file,
                "output": "normalized.jsonl",
                "optional": False
            },
            "L2": {
                "name": "Enrichment",
                "script": "enrich_json.py",  # User's renamed script
                "input": "normalized.jsonl",
                "output": "enriched.jsonl",
                "args": [
                    "--geoip-db", "databases/GeoLite2-City.mmdb",
                    "--asn-db", "databases/GeoLite2-ASN.mmdb",
                    "--tor-list", "databases/tor-exit-nodes.txt",
                    "--reputation-db", "databases/malicious-ips.txt"
                ],
                "optional": False
            },
            "L3": {
                "name": "Event Correlation",
                "script": "correlation_engine.py",  # User's renamed script
                "input": "enriched.jsonl",
                "output": "incidents.jsonl",
                "args": [
                    "--rules", "correlation_rules.yaml"
                ],
                "optional": False
            },
            "L5": {
                "name": "UEBA",
                "script": "ueba.py",
                "input": "enriched.jsonl",  # Parallel from L2
                "output": "ueba_scores.jsonl",
                "args": [
                    "--config", "ueba_config.yaml"
                ],
                "optional": True  # Can run without UEBA
            },
            "L4": {
                "name": "Context & Scoring",
                "script": "context_scorer.py",
                "input": "incidents.jsonl",
                "output": "scored_incidents.jsonl",
                "args": [
                    "--config", "context_config.yaml"
                ],
                "optional": False
            },
            "FUSION": {
                "name": "Final Fusion",
                "script": "fusion.py",
                "input": "scored_incidents.jsonl",
                "output": "correlated_UEBA_alerts.jsonl",
                "args": [
                    "--incidents", "scored_incidents.jsonl",
                    "--ueba", "ueba_scores.jsonl"
                ],
                "optional": False
            }
        }
    
    def run_layer(self, layer_id: str) -> bool:
        """Run a single layer."""
        layer = self.layers[layer_id]
        
        print(f"\n{'='*60}")
        print(f"  Layer {layer_id}: {layer['name']}")
        print(f"{'='*60}")
        
        # Check if input exists
        if not os.path.exists(layer["input"]):
            if layer["optional"]:
                print(f"⚠ Input not found: {layer['input']} (optional layer, skipping)")
                return True
            else:
                print(f"✗ Error: Input file not found: {layer['input']}")
                return False
        
        # Build command
        cmd = [
            "python3",
            layer["script"],
            "--input", layer["input"],
            "--output", layer["output"]
        ]
        
        # Add additional arguments
        if "args" in layer:
            cmd.extend(layer["args"])
        
        # Add --stats flag
        cmd.append("--stats")
        
        print(f"Running: {' '.join(cmd)}")
        print(f"")
        
        # Execute
        try:
            result = subprocess.run(cmd, check=True, capture_output=False, text=True)
            
            # Store result
            self.results[layer_id] = {
                "status": "success",
                "output": layer["output"]
            }
            
            print(f"\n✓ {layer['name']} complete: {layer['output']}")
            return True
        
        except subprocess.CalledProcessError as e:
            print(f"\n✗ Error running {layer['name']}: {e}")
            self.results[layer_id] = {
                "status": "failed",
                "error": str(e)
            }
            return False
        
        except FileNotFoundError:
            print(f"\n✗ Error: Script not found: {layer['script']}")
            self.results[layer_id] = {
                "status": "failed",
                "error": f"Script not found: {layer['script']}"
            }
            return False
    
    def run_pipeline(self):
        """Run the complete pipeline."""
        start_time = datetime.now()
        
        print(f"\n{'#'*60}")
        print(f"#  SIEM Pipeline Orchestrator")
        print(f"#  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'#'*60}")
        
        # Determine which layers to run
        layer_order = ["L1", "L2", "L3", "L5", "L4", "FUSION"]
        
        start_index = layer_order.index(self.start_layer)
        layers_to_run = layer_order[start_index:]
        
        print(f"\nLayers to run: {' → '.join(layers_to_run)}")
        
        # Run layers in order
        for layer_id in layers_to_run:
            success = self.run_layer(layer_id)
            
            if not success and not self.layers[layer_id]["optional"]:
                print(f"\n✗ Pipeline stopped due to error in {layer_id}")
                self.print_summary(success=False)
                return False
        
        # Pipeline complete
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print(f"\n{'#'*60}")
        print(f"#  Pipeline Complete!")
        print(f"#  Duration: {duration:.2f} seconds")
        print(f"{'#'*60}")
        
        self.print_summary(success=True)
        return True
    
    def print_summary(self, success: bool):
        """Print pipeline summary."""
        print(f"\n{'='*60}")
        print(f"  Pipeline Summary")
        print(f"{'='*60}")
        
        for layer_id, result in self.results.items():
            layer = self.layers[layer_id]
            status_symbol = "✓" if result["status"] == "success" else "✗"
            
            print(f"{status_symbol} {layer_id}: {layer['name']}")
            
            if result["status"] == "success":
                print(f"   Output: {result['output']}")
            else:
                print(f"   Error: {result.get('error', 'Unknown error')}")
        
        print(f"{'='*60}")
        
        if success:
            print(f"\n✓ Final output: correlated_UEBA_alerts.jsonl")
            print(f"\nNext steps:")
            print(f"  1. Review alerts: cat correlated_UEBA_alerts.jsonl | jq '.'")
            print(f"  2. Filter by severity: cat correlated_UEBA_alerts.jsonl | jq 'select(.final_assessment.severity == \"P1\")'")
            print(f"  3. Export to SIEM/dashboard")
        else:
            print(f"\n✗ Pipeline did not complete successfully")
            print(f"  Review errors above and fix before retrying")


def main():
    parser = argparse.ArgumentParser(description="SIEM Pipeline Orchestrator")
    parser.add_argument("--input", required=True, help="Input file (raw logs or normalized logs)")
    parser.add_argument("--from", dest="start_layer", default="L1", 
                       choices=["L1", "L2", "L3", "L4", "L5", "FUSION"],
                       help="Start from specific layer")
    parser.add_argument("--all", action="store_true", help="Run complete pipeline from L1")
    
    args = parser.parse_args()
    
    # Determine start layer
    if args.all:
        start_layer = "L1"
    else:
        start_layer = args.start_layer
    
    # Create orchestrator
    orchestrator = PipelineOrchestrator(args.input, start_layer)
    
    # Run pipeline
    success = orchestrator.run_pipeline()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
