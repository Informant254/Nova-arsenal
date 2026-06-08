"""
Nova Conversational Agent v1.0
==============================
Main conversational interface for Nova.

Users can talk to Nova naturally:
"Hey Nova, scan target.com for vulnerabilities"
"Test the API for authentication bypasses"
"What attack paths can I take with admin access?"

Nova understands context, asks clarifying questions,
and executes with full approval workflow.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import json

logger = logging.getLogger(__name__)


@dataclass
class ConversationMessage:
    """Single message in conversation"""
    role: str  # "user" or "nova"
    content: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    intent: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ConversationContext:
    """Maintains conversation state and context"""
    
    def __init__(self, user_api_key: str):
        """Initialize conversation"""
        self.user_api_key = user_api_key
        self.messages: List[ConversationMessage] = []
        self.targets: List[str] = []
        self.scope: Optional[str] = None
        self.risk_level: str = "medium"
        self.authorization_tokens: Dict[str, str] = {}
        self.current_plan: Optional[Any] = None
        self.execution_history: List[Dict] = []
    
    def add_message(
        self,
        role: str,
        content: str,
        intent: Optional[str] = None,
        parameters: Optional[Dict] = None
    ):
        """Add message to conversation"""
        
        msg = ConversationMessage(
            role=role,
            content=content,
            intent=intent,
            parameters=parameters or {}
        )
        
        self.messages.append(msg)
        
        logger.info(f"[{role.upper()}] {content[:100]}...")
    
    def get_recent_context(self, num_messages: int = 5) -> str:
        """Get recent conversation context"""
        
        recent = self.messages[-num_messages:]
        context_lines = []
        
        for msg in recent:
            context_lines.append(f"{msg.role.upper()}: {msg.content}")
        
        return "\n".join(context_lines)
    
    def update_targets(self, targets: List[str]):
        """Update known targets"""
        self.targets = list(set(self.targets + targets))
    
    def export_session(self) -> Dict[str, Any]:
        """Export entire conversation session"""
        
        return {
            "user": self.user_api_key[:10] + "...",
            "started_at": self.messages[0].timestamp if self.messages else None,
            "messages_count": len(self.messages),
            "targets": self.targets,
            "scope": self.scope,
            "risk_level": self.risk_level,
            "executions": len(self.execution_history),
            "messages": [
                {
                    "role": msg.role,
                    "content": msg.content,
                    "timestamp": msg.timestamp,
                    "intent": msg.intent
                }
                for msg in self.messages
            ]
        }


class NovaConversationalAgent:
    """
    Conversational interface to Nova.
    
    Users interact naturally. Nova understands intent,
    generates plans, requests approval, executes.
    """
    
    def __init__(
        self,
        api_key: str,
        nova_agent: Any,
        language_model_router: Any,
        approval_workflow: Any
    ):
        """
        Initialize conversational agent.
        
        Args:
            api_key: User's API key
            nova_agent: NovaKaliAgent instance
            language_model_router: LLM router
            approval_workflow: Approval management
        """
        self.api_key = api_key
        self.nova_agent = nova_agent
        self.llm_router = language_model_router
        self.approval_workflow = approval_workflow
        
        self.context = ConversationContext(api_key)
        self.intent_parser = IntentParser(language_model_router)
        self.clarification_engine = ClarificationEngine(language_model_router)
    
    def chat(self, user_message: str) -> str:
        """
        Main conversation method.
        
        Args:
            user_message: What user said
            
        Returns:
            Nova's response
        """
        
        logger.info(f"User: {user_message}")
        
        # Add to conversation
        self.context.add_message("user", user_message)
        
        # STEP 1: Understand intent
        intent_result = self.intent_parser.parse(
            user_message,
            context=self.context.get_recent_context()
        )
        
        intent = intent_result["intent"]
        parameters = intent_result["parameters"]
        
        logger.info(f"Parsed intent: {intent}")
        
        # Update context with any extracted parameters
        if "targets" in parameters and parameters["targets"]:
            self.context.update_targets(parameters["targets"])
        if "risk_level" in parameters:
            self.context.risk_level = parameters["risk_level"]
        if "scope" in parameters:
            self.context.scope = parameters["scope"]
        
        # STEP 2: Handle based on intent
        if intent == "greeting":
            response = self._handle_greeting()
        
        elif intent == "reconnaissance" or intent == "scanning":
            response = self._handle_scanning_request(parameters)
        
        elif intent == "exploitation":
            response = self._handle_exploitation_request(parameters)
        
        elif intent == "analysis":
            response = self._handle_analysis_request(parameters)
        
        elif intent == "clarification_needed":
            response = self._ask_for_clarification(parameters)
        
        elif intent == "general_question":
            response = self._answer_question(user_message)
        
        else:
            response = self._handle_unknown_intent(user_message)
        
        # Add response to conversation
        self.context.add_message("nova", response, intent=intent)
        
        logger.info(f"Nova: {response[:100]}...")
        
        return response
    
    def _handle_greeting(self) -> str:
        """Handle greeting"""
        return """Hi! I'm Nova, your autonomous penetration testing agent.

I can help you with:
- Reconnaissance (information gathering)
- Vulnerability scanning
- Exploitation testing
- Security analysis and reporting

What would you like to test? (Tell me the target and what you want to do)"""
    
    def _handle_scanning_request(self, parameters: Dict) -> str:
        """Handle scanning/reconnaissance request"""
        
        # Check if we have target
        if not self.context.targets and not parameters.get("targets"):
            return self.clarification_engine.ask_for_target()
        
        targets = parameters.get("targets") or self.context.targets
        
        # Ask for confirmation
        return f"""I'll scan {', '.join(targets[:3])} for vulnerabilities.

Risk level: {self.context.risk_level.upper()}
Scope: {self.context.scope or 'Full target'}

This will involve:
1. Service enumeration
2. Vulnerability scanning  
3. Exploitation testing

Do you want me to proceed? (Y/N)
Or would you like to:
- Adjust risk level (low/medium/high)
- Narrow the scope
- Get more details about the plan"""
    
    def _handle_exploitation_request(self, parameters: Dict) -> str:
        """Handle exploitation request"""
        
        if not self.context.targets and not parameters.get("targets"):
            return self.clarification_engine.ask_for_target()
        
        targets = parameters.get("targets") or self.context.targets
        
        return f"""I can attempt exploitation on {', '.join(targets[:3])}.

⚠️  WARNING: This is AGGRESSIVE testing.
Potential impact:
- Service disruption
- Data modification
- System access

I need explicit approval.

Are you:
1. Authorized to test {targets[0]}?
2. Authorized for exploitation (not just scanning)?
3. Ready for the consequences?

Type APPROVE to proceed, or ask questions."""
    
    def _handle_analysis_request(self, parameters: Dict) -> str:
        """Handle analysis/reporting request"""
        
        if not self.context.targets:
            return self.clarification_engine.ask_for_target()
        
        return f"""I can analyze findings and generate reports for {', '.join(self.context.targets[:3])}.

What would you like me to analyze?
1. Risk assessment
2. Vulnerability summary
3. Attack paths
4. Remediation recommendations
5. All of the above"""
    
    def _ask_for_clarification(self, missing_params: Dict) -> str:
        """Ask user for missing information"""
        
        questions = []
        
        if "targets" in missing_params or not self.context.targets:
            questions.append(self.clarification_engine.ask_for_target())
        
        if "risk_level" in missing_params:
            questions.append(self.clarification_engine.ask_for_risk_level())
        
        if "scope" in missing_params:
            questions.append(self.clarification_engine.ask_for_scope())
        
        return "\n\n".join(questions)
    
    def _answer_question(self, question: str) -> str:
        """Answer general security question"""
        
        logger.info(f"Answering question: {question}")
        
        # Use LLM to answer
        system_prompt = """You are Nova, a security expert.
        Answer security questions accurately and concisely.
        Be practical and actionable."""
        
        answer = self.llm_router.reason(
            f"Question: {question}",
            system_prompt
        )
        
        return answer
    
    def _handle_unknown_intent(self, message: str) -> str:
        """Handle unknown intent"""
        
        return f"""I'm not sure what you want to do. 

Did you mean:
1. Scan a target for vulnerabilities?
2. Test for a specific vulnerability (SQLi, XSS, etc.)?
3. Analyze security of an application?
4. Get security recommendations?

Or ask me a security question. I'm here to help!"""
    
    def approve_and_execute(self, approval_notes: str = "") -> Dict[str, Any]:
        """
        User approves execution of current plan.
        Execute the plan with full audit trail.
        
        Args:
            approval_notes: Why user is approving
            
        Returns:
            Execution results
        """
        
        if not self.context.current_plan:
            return {
                "status": "ERROR",
                "message": "No plan to execute. Generate a plan first."
            }
        
        logger.warning(f"APPROVAL: User approved execution")
        logger.warning(f"  Targets: {self.context.targets}")
        logger.warning(f"  Risk: {self.context.risk_level}")
        
        # Execute with approval
        try:
            result = self.nova_agent.execute_with_approval(
                self.context.current_plan,
                user_approval=True,
                approval_comments=approval_notes
            )
            
            # Record in history
            self.context.execution_history.append({
                "timestamp": datetime.now().isoformat(),
                "targets": self.context.targets,
                "result": result
            })
            
            return result
        
        except Exception as e:
            logger.error(f"Execution failed: {e}")
            return {
                "status": "ERROR",
                "message": f"Execution failed: {e}"
            }
    
    def reject_plan(self, reason: str) -> str:
        """
        User rejects the plan.
        
        Args:
            reason: Why it was rejected
            
        Returns:
            Confirmation message
        """
        
        logger.info(f"Plan rejected: {reason}")
        
        self.context.current_plan = None
        
        return f"Plan rejected. {reason}\n\nWhat would you like to do instead?"
    
    def get_history(self) -> str:
        """Get conversation history"""
        
        lines = []
        for msg in self.context.messages:
            lines.append(f"{msg.role.upper()}: {msg.content}")
        
        return "\n\n".join(lines)
    
    def export_session(self) -> Dict[str, Any]:
        """Export conversation session"""
        
        return self.context.export_session()


class IntentParser:
    """Parses user intent using LLM"""
    
    def __init__(self, language_model_router: Any):
        """Initialize parser"""
        self.llm_router = language_model_router
        
        self.intent_keywords = {
            "greeting": ["hi", "hello", "hey", "start", "help"],
            "reconnaissance": ["recon", "enumerate", "discover", "find", "what can"],
            "scanning": ["scan", "test", "check", "audit", "look for"],
            "exploitation": ["exploit", "hack", "attack", "compromise", "penetrate"],
            "analysis": ["analyze", "report", "assess", "summarize", "impact"],
            "question": ["what", "how", "why", "explain", "tell me"]
        }
    
    def parse(self, user_message: str, context: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse user intent and extract parameters.
        
        Args:
            user_message: What user said
            context: Recent conversation context
            
        Returns:
            Intent and parameters
        """
        
        # Quick keyword check
        intent = self._quick_intent_check(user_message)
        
        if intent == "unknown":
            # Use LLM for complex intent
            intent = self._llm_intent_parse(user_message, context)
        
        # Extract parameters
        parameters = self._extract_parameters(user_message)
        
        return {
            "intent": intent,
            "parameters": parameters
        }
    
    def _quick_intent_check(self, message: str) -> str:
        """Quick keyword-based intent check"""
        
        message_lower = message.lower()
        
        for intent, keywords in self.intent_keywords.items():
            if any(kw in message_lower for kw in keywords):
                return intent
        
        return "unknown"
    
    def _llm_intent_parse(self, message: str, context: Optional[str]) -> str:
        """Use LLM for intent parsing"""
        
        system_prompt = """Determine the user's intent. Return only one word.
        Options: greeting, reconnaissance, scanning, exploitation, analysis, 
        question, clarification_needed, general_question"""
        
        prompt = f"""User message: "{message}"

What is their intent? Return single word only."""
        
        try:
            response = self.llm_router.reason(prompt, system_prompt).strip().lower()
            return response
        except:
            return "general_question"
    
    def _extract_parameters(self, message: str) -> Dict[str, Any]:
        """Extract parameters from message"""
        
        import re
        
        parameters = {
            "targets": [],
            "risk_level": None,
            "scope": None,
            "requirements": []
        }
        
        # Extract URLs
        urls = re.findall(r'https?://[^\s]+', message)
        parameters["targets"].extend(urls)
        
        # Extract IPs
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', message)
        parameters["targets"].extend(ips)
        
        # Extract domains
        domains = re.findall(
            r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}',
            message.lower()
        )
        parameters["targets"].extend([d for d in domains if d not in urls])
        
        # Extract risk level
        message_lower = message.lower()
        if any(w in message_lower for w in ["high", "aggressive", "maximum"]):
            parameters["risk_level"] = "high"
        elif any(w in message_lower for w in ["low", "safe", "careful"]):
            parameters["risk_level"] = "low"
        else:
            parameters["risk_level"] = "medium"
        
        # Remove duplicates
        parameters["targets"] = list(set(parameters["targets"]))
        
        return parameters


class ClarificationEngine:
    """Asks clarifying questions when needed"""
    
    def __init__(self, language_model_router: Any):
        """Initialize"""
        self.llm_router = language_model_router
    
    def ask_for_target(self) -> str:
        """Ask for target"""
        return "What system would you like me to test? (URL, IP, or domain)"
    
    def ask_for_risk_level(self) -> str:
        """Ask for risk level"""
        return """How aggressive should I be?
1. LOW - Safe, information gathering only
2. MEDIUM - Active testing, some potential impact
3. HIGH - Exploitation allowed, significant impact possible"""
    
    def ask_for_scope(self) -> str:
        """Ask for scope"""
        return """What's the scope?
1. Just this endpoint/URL
2. This domain and subdomains
3. This IP range
4. Everything accessible from the app"""
    
    def confirm_dangerous_action(self, action: str) -> str:
        """Confirm dangerous action"""
        return f"""⚠️  WARNING: {action}

This could cause:
- Service disruption
- Data loss
- System compromise

Are you absolutely sure? Type CONFIRM to proceed."""


# Example usage
if __name__ == "__main__":
    print("\n=== NOVA CONVERSATIONAL AGENT ===\n")
    
    # Mock setup
    class MockLLMRouter:
        def reason(self, prompt, system_prompt=None):
            return "Mock response"
    
    # In real usage:
    # agent = NovaConversationalAgent(
    #     api_key="user_key",
    #     nova_agent=nova_agent_instance,
    #     language_model_router=llm_router,
    #     approval_workflow=approval_workflow
    # )
    
    # conversation = agent.chat("Scan target.com for vulnerabilities")
    # print(conversation)
