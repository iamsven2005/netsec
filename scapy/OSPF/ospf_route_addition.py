from __future__ import annotations


def normalize_metric(metric):
    metric_value = int(metric)
    if not 0 <= metric_value <= 0xFFFF:
        raise ValueError("Metric must be between 0 and 65535.")
    return metric_value


def add_router_stub_route(context, prefix, mask, metric, *, normalize_network, ospf_link_cls, next_lsa_sequence, build_router_lsa, upsert_lsa, flood_lsa_packets, log_message):
    network_prefix, network_mask = normalize_network(prefix, mask)
    stub_link = ospf_link_cls(type=3, id=network_prefix, data=network_mask, metric=normalize_metric(metric))
    with context["lock"]:
        context["manual_router_links"] = [
            existing_link.copy()
            for existing_link in context["manual_router_links"]
            if (existing_link.id, existing_link.data) != (stub_link.id, stub_link.data)
        ]
        context["manual_router_links"].append(stub_link.copy())
        sequence_number = next_lsa_sequence(context, 1, context["router_id"], context["router_id"])
        router_lsa = build_router_lsa(context, sequence_number=sequence_number)
        upsert_lsa(context, router_lsa)
    flooded = flood_lsa_packets(context, [router_lsa])
    scope_text = "and flooded to FULL neighbors" if flooded else "in the local LSDB only"
    log_message(
        f"[ROUTES] Added Router-LSA route net={stub_link.id} mask={stub_link.data} "
        f"metric={stub_link.metric} seq=0x{router_lsa.seq:08x} {scope_text}."
    )
    return router_lsa


def prompt_and_add_router_stub_route(context, input_func, log_message, *, normalize_network, ospf_link_cls, next_lsa_sequence, build_router_lsa, upsert_lsa, flood_lsa_packets,):
    try:
        prefix = input_func("  Router-LSA network: ").strip()
        mask = input_func("  Router-LSA mask: ").strip()
        metric_text = input_func("  Router-LSA metric [10]: ").strip()
        metric = int(metric_text) if metric_text else 10
        add_router_stub_route(context, prefix, mask, metric, normalize_network=normalize_network, ospf_link_cls=ospf_link_cls, next_lsa_sequence=next_lsa_sequence, build_router_lsa=build_router_lsa, upsert_lsa=upsert_lsa, flood_lsa_packets=flood_lsa_packets, log_message=log_message)
    except ValueError as exc:
        log_message(f"[MENU] Could not update Router-LSA: {exc}")
    except EOFError:
        return
