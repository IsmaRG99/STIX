# Autor: Ismael Rojas Gonzalez

from stix2 import Campaign, ThreatActor, Vulnerability, Incident, Malware, Tool, Report, Relationship, Bundle, AttackPattern, Identity

threat_actor = ThreatActor(
    name="Grupo APT Atacante",
    description="Grupo APT que realizó el ataque."
)

attack_pattern = AttackPattern(
   name="Phishing",
   description="TTP de la que abusan los atacantes para entregar el malware."
)

tool = Tool(
    name="Outlook",
    description="El grupo APT Atancate hizo uso de Outlook para llevar a cabo su phishing."
)

malware = Malware(
    name="Malware instalado",
    description="Malware instalado por el correo de phishing enviado.",
    is_family = False
)

victima=Identity(
   name="Usuario víctima"
)

rel_actor_pattern = Relationship(relationship_type="uses", source_ref=threat_actor.id, target_ref=attack_pattern.id)
rel_actor_victima = Relationship(relationship_type="targets", source_ref=threat_actor.id, target_ref=victima.id)
rel_pattern_tool = Relationship(relationship_type="uses", source_ref=attack_pattern.id, target_ref=tool.id)
rel_tool_malware = Relationship(relationship_type="delivers", source_ref=tool.id, target_ref=malware.id)
rel_tool_victima = Relationship(relationship_type="targets", source_ref=tool.id, target_ref=victima.id)
rel_malware_actor = Relationship(relationship_type="authored-by", source_ref=malware.id, target_ref=threat_actor.id)
rel_malware_victima = Relationship(relationship_type="targets", source_ref=malware.id, target_ref=victima.id)

bundle = Bundle(threat_actor, attack_pattern, malware, tool, victima, rel_actor_pattern, rel_actor_victima, rel_pattern_tool, rel_tool_malware, rel_tool_victima, rel_malware_actor, rel_malware_victima)

print(bundle.serialize(pretty=True))

