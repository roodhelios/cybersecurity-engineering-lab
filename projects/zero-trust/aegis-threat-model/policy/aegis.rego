package aegis.authorization

import rego.v1

default decision := {"effect": "deny", "reason": "default_deny"}

role_allowed if {
    some role in data.agent_roles[input.agent_id]
    role in data.tools[input.tool_name].roles
}

requires_step_up if {
    role_allowed
    data.tools[input.tool_name].sensitivity == "high"
    input.risk_score >= data.thresholds.step_up_risk
    not input.step_up_token_valid
}

decision := {"effect": "deny", "reason": "unknown_tool"} if {
    not data.tools[input.tool_name]
}

decision := {"effect": "deny", "reason": "role_not_allowed"} if {
    data.tools[input.tool_name]
    not role_allowed
}

decision := {"effect": "step_up", "reason": "step_up_required"} if {
    requires_step_up
}

decision := {"effect": "allow", "reason": "authorized"} if {
    role_allowed
    not requires_step_up
}
