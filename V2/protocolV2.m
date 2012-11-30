-------------------------------------------------------------------------------
--
-- Murphi Model of an AWESOME AND AS YET UNNAMED protocol
--
-------------------------------------------------------------------------------
--
-- version:	1.0
--
-- written by: Ashley Oudenne and Jerremy Adams
-- date: Nov. 30, 2012
-- affiliation: The University of Texas at Austin
--
-------------------------------------------------------------------------------
--
-- The following steps of the protocol are modeled:
--
-- 1. A -> B: {Kab, A}_Kb,	--A sends B the secret key unencrypted
-- 2. B -> A: {Kab, B}_Ka,	--B sends A the secret key back for confirmation
--
-- A: initiator, B: responder
--
-------------------------------------------------------------------------------
--
-- This version has the following features:
--     *the intruder always intercepts
--
-------------------------------------------------------------------------------
--
-- Constants, Types, and Variables:
--
-------------------------------------------------------------------------------


-------------------------------------------------------------------------------
const

   NumInitiators: 1;	-- number of initiators
   NumResponders: 1;	-- number of responders
   NumIntruders:  1;	-- number of intruders
   NetworkSize:	  1;	-- max number of outstanding messages in network
   MaxKnowledge:  10;	-- max number of messages intruder can remember

-------------------------------------------------------------------------------
type

   InitiatorId:	  scalarset(NumInitiators);
   ResponderId:	  scalarset(NumResponders);
   IntruderId:	  scalarset(NumIntruders);

   AgentId:	     union{InitiatorId, ResponderId, IntruderId};

   MessageType: enum{
      M_KeyAddressE		--Kab:  Unencrypted Key
   };

   Message: record
      source:	  AgentId;	 --actual source of message
      dest:	      AgentId;	 --intended destination of message
      msgKey:     AgentId;   --key used to encrypt message   
      secretKey:  AgentId;	 --secret key being sent
      senderE:	  AgentId;	 --encrypted sender of message
      mType:	  MessageType;	 --type of message
   end;

   InitiatorStates : enum {
      I_SLEEP,                     -- state after initialization
      I_WAIT,                      -- waiting for response from responder
      I_COMMIT                     -- initiator commits to session
   };   

   Initiator : record
      state:     InitiatorStates;
      responder: AgentId;          -- agent who first responded
      secretKey: AgentId;
   end;

   ResponderStates : enum {
      R_SLEEP,
      R_WAIT,
      R_COMMIT
   };
   Responder : record
      state:	  ResponderStates;
      initiator:  AgentId;
      secretKey:  AgentId;
   end;

   Intruder : record
      nonces:	  array[AgentId] of boolean;           -- known nonces
      keys:	  array[AgentId] of boolean;
      messages:	  multiset[MaxKnowledge] of Message;   -- known messages
   end;

-------------------------------------------------------------------------------
var                                         -- state variables for
   net: multiset[NetworkSize] of Message;    --  network
   ini: array[InitiatorId] of Initiator;     --  initiators
   res: array[ResponderId] of Responder;     --  responders
   int: array[IntruderId] of Intruder;       --  intruders
-------------------------------------------------------------------------------


-------------------------------------------------------------------------------
-- Rules
-------------------------------------------------------------------------------

-------------------------------------------------------------------------------
--Behavior of Initiators

--initiator i starts protocol with responder or intruder j (step 1)

ruleset i:InitiatorId do
   ruleset j: AgentId do
      rule "initiator starts protocol (step 1)"

	 ini[i].state = I_SLEEP &
	 !ismember(j,InitiatorId) &
	 multisetcount (l:net, true)<NetworkSize


      ==>

      var outM: Message;   -- outgoing message
      
      begin
	 undefine outM;
	 outM.source	:= i;
	 outM.dest	    := j;
     outM.msgKey    := j;
	 outM.secretKey := i;
	 outM.senderE	:= i;
	 outM.mType	:=M_KeyAddressE;

	 multisetadd(outM, net);

	 ini[i].state := I_WAIT;
	 ini[i].responder := j;
	 ini[i].secretKey := i;

      end;
   end;
end;

--initiator i reacts to secret key received (step 3-ish)
ruleset i:InitiatorId do
   choose j:net do
      rule "initiator reacts to secret key received (step 3-ish)"

	 ini[i].state = I_WAIT &
	 net[j].dest = i &
	 ismember(net[j].source, IntruderId)
      ==>

      var
	 inM: Message;	--incoming message

      begin
	 if ((inM.secretKey = ini[i].secretKey) & (inM.msgKey=i) & (inM.senderE = ini[i].responder))then
	    ini[i].state := I_COMMIT;
	 else
	    --error "initiator received unintended message"
	 end;
      end;
   end;
end;

-------------------------------------------------------------------------------
--behavior of responders

--responder i reacts to initiator's secret key
ruleset i: ResponderId do
   choose j:net do
      rule "responder reacts to initiator's secret key"


	 res[i].state = R_SLEEP &
	 net[j].dest = i &
	 ismember(net[j].source, IntruderId)
      ==>

      var
	 outM: Message;	   --outgoing message
	 inM:  Message;	   --incoming message

      begin
	 inM := net[j];
	 if ((inM.mType = M_KeyAddressE) & (inM.msgKey = i)) then
	    undefine outM;
	    outM.source	   := i;
	    outM.dest	   := inM.senderE;
            outM.msgKey    := inM.senderE;
	    outM.secretKey := inM.secretKey;
	    outM.senderE	   := i;
	    outM.mType	   := M_KeyAddressE;

	    multisetremove(j, net);
	    multisetadd(outM, net);

	    res[i].state      := R_COMMIT;
   	    res[i].initiator  := inM.senderE;
	    res[i].secretKey  := inM.secretKey;
	 end;
      end;
   end;
end;	 
      
-------------------------------------------------------------------------------
--Behavior of Intruders

--intruder i intercepts message
ruleset i: IntruderId do
   choose j: net do
      rule "Intruder intercepts"
	 !ismember(net[j].source, IntruderId) --not intruder messages
      ==>
      var
	 temp: Message;

      begin
          alias msg: net[j] do	 --message that is intercepted
	    if(( msg.mType = M_KeyAddressE)  & (msg.msgKey = i)) then
              int[i].keys[temp.secretKey] := true;
            end;
            alias messages: int[i].messages do
	    temp := msg;
	    undefine temp.source;
            undefine temp.dest;
            if multisetcount(l:messages, --add only if intruder has room
                messages[l].secretKey = temp.secretKey &
                messages[l].mType = temp.mType &
                messages[l].msgKey = temp.msgKey &
                messages[l].senderE = temp.senderE) = 0 then
                multisetadd(temp, int[i].messages);
            end;
	    end;
	    multisetremove(j, net);
	 end;
      end;
   end;
end;

--intruder i sends recorded message
ruleset i: IntruderId do
   choose j: int[i].messages do	    --choose message
      ruleset k: AgentId do	    --send it to everyone
	 rule "Intruder sends recorded message"

	    !ismember(k, IntruderId) &
	    multisetcount (l:net, true) < NetworkSize

	 ==>

	 var
	    outM: Message;
   
	 begin

	    outM  := int[i].messages[j];
	    outM.source := i;
	    outM.dest	:= k;

	    multisetadd(outM, net);
	 end;  
      end;
   end;
end;

--intruder i generates new message with keys it knows
ruleset i: IntruderId do
   ruleset j: AgentId do	    --dest
      ruleset k: AgentId do	    --key
	 ruleset l: AgentId do	    --sender
	    ruleset m: MessageType do  --message type
	       rule "intruder generates new message"

		  !ismember(j, IntruderId) &
		  int[i].keys[k] = true &
		  multisetcount (t:net, true) < NetworkSize

	       ==>

	       var 
		  outM: Message;

	       begin
		  undefine outM;
		  outM.source := i;
		  outM.dest   := j;
		  outM.mType  := m;
                  outM.msgKey := j;
		  outM.secretKey := k;
		  outM.senderE := l;

		  multisetadd(outM, net);
	       end;
	    end;
	 end;
      end;
   end;
end;

-------------------------------------------------------------------------------
-- Start State
-------------------------------------------------------------------------------

startstate
   -- initialize initiators
   undefine ini;
   for i: InitiatorId do
      ini[i].state	:= I_SLEEP;
      ini[i].responder	:= i;
      ini[i].secretKey	:= i; 
   end;

   --initialize responders
   undefine res;
   for i: ResponderId do
      res[i].state	:= R_SLEEP;
      res[i].initiator	:= i;
      res[i].secretKey	:= i;
   end;

   --initialize intruders
   undefine int;
   for i:IntruderId do
      for j:AgentId do
	 int[i].keys[j] := false;
      end;
      int[i].keys[i] := true;
   end;

   --initialize network
   undefine net;
end;

-------------------------------------------------------------------------------
-- Invariants
-------------------------------------------------------------------------------
invariant "responder correctly authenticated"
   forall i: InitiatorId do
      ini[i].state = I_COMMIT &
      ismember(ini[i].responder, ResponderId)
      ->
      res[ini[i].responder].initiator = i &
      (res[ini[i].responder].state = R_COMMIT)
   end;

invariant "initator correctly authenticated"
   forall r: ResponderId do
      res[r].state = R_COMMIT &
      ismember(res[r].initiator, InitiatorId)
      ->
      ini[res[r].initiator].responder = r &
      (ini[res[r].initiator].state = I_COMMIT|
      ini[res[r].initiator].state = I_WAIT)
   end;

invariant "secret key unknown"
   forall i: IntruderId do
      forall j: AgentId do
	 !ismember(j, IntruderId)
	 ->
	 int[i].keys[j] = false
      end
   end;

