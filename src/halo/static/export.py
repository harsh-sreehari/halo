from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Any

from halo.static.graph import CodeKnowledgeGraph


def export_ckg_to_cytoscape(ckg: CodeKnowledgeGraph) -> dict[str, Any]:
    """
    Export a CodeKnowledgeGraph (CKG) into standard Cytoscape.js node-link JSON format.

    Returns:
        {
            "elements": {
                "nodes": [
                    {"data": {"id": ..., "node_type": ..., ...}}
                ],
                "edges": [
                    {"data": {"id": ..., "source": ..., "target": ..., "edge_type": ..., ...}}
                ]
            }
        }
    """
    nodes_list: list[dict[str, Any]] = []
    edges_list: list[dict[str, Any]] = []

    # Export Nodes
    for node_id in ckg.graph.nodes:
        if node_id in ckg.nodes:
            node_obj = ckg.nodes[node_id]
            node_data = node_obj.model_dump(mode="json")
        else:
            raw_attrs = dict(ckg.graph.nodes[node_id])
            raw_attrs.pop("data", None)
            node_data = {}
            for k, v in raw_attrs.items():
                if isinstance(v, Enum):
                    node_data[k] = v.value
                elif isinstance(v, (str, int, float, bool, list, dict)) or v is None:
                    node_data[k] = v
                else:
                    node_data[k] = str(v)

        node_data["id"] = str(node_id)
        nodes_list.append({"data": node_data})

    # Export Edges
    for u, v, edge_attrs in ckg.graph.edges(data=True):
        edge_data: dict[str, Any] = {}
        for k, v_attr in edge_attrs.items():
            if isinstance(v_attr, Enum):
                edge_data[k] = v_attr.value
            elif isinstance(v_attr, (str, int, float, bool, list, dict)) or v_attr is None:
                edge_data[k] = v_attr
            else:
                edge_data[k] = str(v_attr)

        edge_data["source"] = str(u)
        edge_data["target"] = str(v)
        if "id" not in edge_data:
            edge_type_suffix = f":{edge_data['edge_type']}" if "edge_type" in edge_data else ""
            edge_data["id"] = f"{u}->{v}{edge_type_suffix}"

        edges_list.append({"data": edge_data})

    return {
        "elements": {
            "nodes": nodes_list,
            "edges": edges_list,
        }
    }


def export_ckg_to_json(ckg: CodeKnowledgeGraph, indent: int = 2) -> str:
    """Export CKG to Cytoscape JSON string."""
    return json.dumps(export_ckg_to_cytoscape(ckg), indent=indent)


def export_ckg_to_cytoscape_file(
    ckg: CodeKnowledgeGraph, output_path: str | Path, indent: int = 2
) -> Path:
    """Export CKG to Cytoscape JSON file on disk."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(export_ckg_to_json(ckg, indent=indent), encoding="utf-8")
    return path
