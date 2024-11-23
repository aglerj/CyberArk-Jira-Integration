using System;
using System.IO;
using System.Xml;
using System.Net;
using System.Globalization;
using System.Text.RegularExpressions;
using CyberArk.PasswordVault.PublicInterfaces;
using Newtonsoft.Json;
using System.Net.Sockets;
using Jira.TicketingValidation;
using ServiceNow.Api;

namespace TicketingValidation
{

    #region Public Class - Main
    public class TicketingValidator : ITicketVaildatorEx
    {

        #region Public Parameters
        //Use TLS 1.2
        public const System.Net.SecurityProtocolType SecurityProtocol = SecurityProtocolType.Tls12;

        //PVWA hostname
        public string pvwaHostname = System.Net.Dns.GetHostName();

        //set Ticketing Parameters
        public string checkParameters = string.Empty;
        public string ticketingID = string.Empty;
        public string ticketingSys = string.Empty;
        public string ticketingAssignee = string.Empty;
        public DateTime ticketStartTime = new DateTime();
        public DateTime ticketEndTime = new DateTime();

        // Set additional Ticketing Parameters
        public string ServiceNowURL = string.Empty;
        public string OAuthURL = string.Empty;
        public bool validateconfigurationitem = false;
        public bool validateassignedto = false;
        public bool validateassignmentGroup = false;
        public bool MaintenanceModeEnabled = false;
        public bool AuditOnlyMode = false;
        public bool EnableLogging = false;
        public string ChangeTicketFormat = string.Empty;
        public string ChangeTaskTicketFormat = string.Empty;
        public string RequestTicketFormat = string.Empty;
        public string RequestedItemTicketFormat = string.Empty;
        public string CatalogTaskTicketFormat = string.Empty;
        public string ProblemTicketFormat = string.Empty;
        public string ProblemTaskTicketFormat = string.Empty;
        public string ServiceCatalogTaskTicketFormat = string.Empty;
        public string IncidentTaskTicketFormat = string.Empty;
        public string IncidentTicketFormat = string.Empty;
        public bool UpdateTicketWorkNotes = false;
        //public string UpdateTicketWorkNotesParameters = string.Empty;
        public int ServiceNowApiCallTimeout = 0;

        //set Info from CyberArk Interface
        public string cybrSafeName = string.Empty;
        public string cybrObjectName = string.Empty;
        public string cybrMachineAddress = string.Empty;
        public string cybrTransparentMachineAddress = string.Empty;
        public string cybrRequestingUser = string.Empty;
        public bool cybrDualControl = false;
        public bool cybrDualControlRequestConfirmed = false;
        public string cybrReason = string.Empty;
        public string cybrUsername = string.Empty;
        public string cybrRequesterName = string.Empty;
        public string cybrEmail = string.Empty;
        public string cybrPolicy = string.Empty;
        public string cybrTower = string.Empty;
        public string cybrHostname = string.Empty;
        public string cybrDatabase = string.Empty;
        public string cybrPort = string.Empty;

        //set api logon
        public bool chkLogonToTicketingSystem = false;
        public string ServiceNowlogonAddress = string.Empty;
        public string ServiceNowlogonUsername = string.Empty;
        public string ServiceNowlogonPassword = string.Empty;

        //set error messages
        public string msgInvalidTicket = string.Empty;
        public string msgInvalidTicketFormat = string.Empty;
        public string msgInvalidTicketStatus = string.Empty;
        public string msgInvalidMachine = string.Empty;
        public string msgInvalidAccessTime = string.Empty;
        public string msgInvalidImplementer = string.Empty;
        public string msgConnectionError = string.Empty;

        //set bypass ticket code
        public string bypassServiceNowValidationCode = string.Empty;
        public string bypassServiceNowValidateTimeStampCode = string.Empty;

        //set create ticket code;
        public string createServiceNowIncValidationCode = string.Empty;

        //set allowed Ticket Status
        public string allowedChangeTicketStatus = string.Empty;
        public string allowedServiceRequestTicketStatus = string.Empty;
        public string allowedIncidentTicketStatus = string.Empty;
        public string allowedProblemTicketStatus = string.Empty;

        //set allowTicketFormatRegex
        public string allowTicketFormatRegex = string.Empty;

        //set check condition bool
        public bool enChkCI_CHG = true;
        public bool enChkCI_INC = true;
        public bool enChkCI_RITM = true;
        public bool enChkCI = true; //deduced based on enChkCI_CHG, enChkCI_INC, enChkCI_RITM
        public bool enChkTime = true;
        public bool enChkImplementer = true;

        //set ServiceNow api parameter
        public string ServiceNowApiKey_CI = string.Empty;
        public string ServiceNowApiKey_StartTime = string.Empty;
        public string ServiceNowApiKey_EndTime = string.Empty;
        public int ServiceNowApiCall_Timeout = 10000; //10 Second by default

        //internal paramater
        public string logMessage = string.Empty;
        public string errorMessage = string.Empty;
        public string auditMessage = string.Empty;

        //CMDB configItemID
        public string configItemID = string.Empty;

        //EmergencyMode
        public bool emergencyMode = false;
        public bool bypassValidateTimeMode = false;

        //Logging
        public string logFilePath = string.Empty;
        #endregion

        #region Public Function ValidateTicket
        public bool ValidateTicket(IValidationParametersEx parameters, out ITicketOutput ticketingOutput)
        {

            #region Init/Declare

            // Validation result (the return value) - will contain true if validate succeed, false otherwise
            bool bValid = false;

            //Set ticketing output
            ticketingOutput = new TicketOutput();

            // Kept the default ParseXML input & output.But parameters are parse to the public variables
            ParseXmlParameters(parameters.XmlNodeParameters);

            //Fetch Service accout
            ITicketingConnectionAccount connectionAccount = parameters.TicketingConnectionAccount;

            //Fetch from PVWA
            cybrSafeName = parameters.SafeName;
            cybrObjectName = parameters.ObjectName;
            cybrMachineAddress = parameters.MachineAddress.Trim().ToUpper();
            cybrTransparentMachineAddress = parameters.TransparentMachineAddress.Trim().ToUpper();
            cybrDualControl = parameters.DualControl;
            cybrDualControlRequestConfirmed = parameters.DualControlRequestConfirmed;
            cybrReason = parameters.ProvidedReason;
            cybrUsername = parameters.UserName;
            cybrRequesterName = parameters.RequestingUserFirstName + " " + parameters.RequestingUserSurname;
            cybrEmail = parameters.RequestingUserEmail;
            cybrPolicy = parameters.PolicyId;
            cybrRequestingUser = parameters.RequestingUser.Trim().ToUpper();

            if (parameters.AdditionalProperties.ContainsKey("Tower"))
            {
                cybrTower = parameters.AdditionalProperties["Tower"];
            }
            if (parameters.AdditionalProperties.ContainsKey("Hostname"))
            {
                cybrHostname = parameters.AdditionalProperties["Hostname"];
            }
            if (parameters.AdditionalProperties.ContainsKey("Database"))
            {
                cybrDatabase = parameters.AdditionalProperties["Database"];
            }
            if (parameters.AdditionalProperties.ContainsKey("Port"))
            {
                cybrPort = parameters.AdditionalProperties["Port"];
            }

            //set ticketing parameter
            ticketingSys = parameters.SystemName.ToUpper();
            ticketingID = parameters.TicketId.Trim().ToUpper();

            //Set API Logon Parameters
            ServiceNowlogonAddress = parameters.TicketingConnectionAccount.Address;
            if (parameters.TicketingConnectionAccount.Properties.ContainsKey("URL"))
            {
                ServiceNowlogonAddress = parameters.TicketingConnectionAccount.Properties["URL"];
            }
            ServiceNowlogonUsername = parameters.TicketingConnectionAccount.UserName;
            ServiceNowlogonPassword = parameters.TicketingConnectionAccount.Password;

            //Audit
            auditMessage = string.Format("PVWA={0} | Input={1} | DualControl={2} | DualControlRequestConfirmed={3} |", pvwaHostname, ticketingID, cybrDualControl, cybrDualControlRequestConfirmed);

            #endregion

            #region Log
            LogWrite("[ Initializing process ] ...");

            LogWrite("[ Fetching PVWA Hostname ] ...");
            LogWrite(string.Format("{0}: {1}", "PVWA Hostname", pvwaHostname));

            LogWrite("[ Fetching XML parameter ]...");
            LogWrite(string.Format("{0}: {1}", "allowedChangeTicketStatus", allowedChangeTicketStatus));
            LogWrite(string.Format("{0}: {1}", "allowedServiceRequestTicketStatus", allowedServiceRequestTicketStatus));
            LogWrite(string.Format("{0}: {1}", "allowedIncidentTicketStatus", allowedIncidentTicketStatus));
            LogWrite(string.Format("{0}: {1}", "allowedProblemTicketStatus", allowedProblemTicketStatus));
            LogWrite(string.Format("{0}: {1}", "msgInvalidTicket", msgInvalidTicket));
            LogWrite(string.Format("{0}: {1}", "msgInvalidTicketFormat", msgInvalidTicketFormat));
            LogWrite(string.Format("{0}: {1}", "msgInvalidTicketStatus", msgInvalidTicketStatus));
            LogWrite(string.Format("{0}: {1}", "msgConnectionError", msgConnectionError));
            LogWrite(string.Format("{0}: {1}", "msgInvalidAccessTime", msgInvalidAccessTime));
            LogWrite(string.Format("{0}: {1}", "msgInvalidMachine", msgInvalidMachine));
            LogWrite(string.Format("{0}: {1}", "msgInvalidImplementer", msgInvalidImplementer));
            LogWrite(string.Format("{0}: {1}", "msgInvalidImplementer", chkLogonToTicketingSystem));
            LogWrite(string.Format("{0}: {1}", "enChkTime", enChkTime));
            LogWrite(string.Format("{0}: {1}", "enChkCI_CR", enChkCI_CR));
            LogWrite(string.Format("{0}: {1}", "enChkCI_SR", enChkCI_SR));
            LogWrite(string.Format("{0}: {1}", "enChkCI_INC", enChkCI_INC));
            LogWrite(string.Format("{0}: {1}", "enChkImplementer", enChkImplementer));
            LogWrite(string.Format("{0}: {1}", "bypassServiceNowValidationCode", bypassServiceNowValidationCode));
            LogWrite(string.Format("{0}: {1}", "createServiceNowIncValidationCode", createServiceNowIncValidationCode));
            LogWrite(string.Format("{0}: {1}", "ServiceNowApiCall_Timeout", ServiceNowApiCall_Timeout));

            //Added
            LogWrite(string.Format("{0}: {1}", "ServiceNowURL", ServiceNowURL));
            LogWrite(string.Format("{0}: {1}", "OAuthURL", OAuthURL));
            LogWrite(string.Format("{0}: {1}", "validateconfigurationitem", validateconfigurationitem));
            LogWrite(string.Format("{0}: {1}", "validateassignedto", validateassignedto));
            LogWrite(string.Format("{0}: {1}", "MaintenanceModeEnabled", MaintenanceModeEnabled));
            LogWrite(string.Format("{0}: {1}", "AuditOnlyMode", AuditOnlyMode));
            LogWrite(string.Format("{0}: {1}", "EnableLogging", EnableLogging));
            LogWrite(string.Format("{0}: {1}", "ChangeTaskTicketFormat", ChangeTaskTicketFormat));
            LogWrite(string.Format("{0}: {1}", "RequestTicketFormat", RequestTicketFormat));
            LogWrite(string.Format("{0}: {1}", "RequestedItemTicketFormat", RequestedItemTicketFormat));
            LogWrite(string.Format("{0}: {1}", "CatalogTaskTicketFormat", CatalogTaskTicketFormat));
            LogWrite(string.Format("{0}: {1}", "ProblemTicketFormat", ProblemTicketFormat));
            LogWrite(string.Format("{0}: {1}", "ProblemTaskTicketFormat", ProblemTaskTicketFormat));
            LogWrite(string.Format("{0}: {1}", "ServiceCatalogTaskTicketFormat", ServiceCatalogTaskTicketFormat));
            LogWrite(string.Format("{0}: {1}", "UpdateTicketWorkNotes", UpdateTicketWorkNotes));
            //LogWrite(string.Format("{0}: {1}", "UpdateTicketWorkNotesParameters", UpdateTicketWorkNotesParameters));
            LogWrite(string.Format("{0}: {1}", "ServiceNowApiCallTimeout", ServiceNowApiCallTimeout));

            LogWrite("[ Fetching Ticketing connection account ]");
            LogWrite(string.Format("{0}: {1}", "ServiceNowlogonAddress", ServiceNowlogonAddress));
            LogWrite(string.Format("{0}: {1}", "ServiceNowlogonUsername", ServiceNowlogonUsername));
            LogWrite(string.Format("{0}: {1}", "ServiceNow Object Name", parameters.TicketingConnectionAccount.ObjectName));
            LogWrite(string.Format("{0}: {1}", "ServiceNow Safe Name", parameters.TicketingConnectionAccount.Safe));
            LogWrite(string.Format("{0}: {1}", "ServiceNow Folder Name", parameters.TicketingConnectionAccount.Folder));

            LogWrite("[ Fetching Ticketing connection account -> Additional Properties ]");
            foreach (var item in parameters.TicketingConnectionAccount.Properties)
            {
                if (item.Key == "LastFailDate" || item.Key == "LastSuccessChange" || item.Key == "LastSuccessReconciliation")
                {
                    LogWrite(string.Format("{0}: {1}", item.Key, UnixTimeStampToDateTime(item.Value)));
                }
                else
                {
                    LogWrite(string.Format("{0}: {1}", item.Key, item.Value));
                }

            }

            LogWrite("[ Fetching ticketing parameter ] ");
            LogWrite(string.Format("{0}: {1}", "TicketId", parameters.TicketId));
            LogWrite(string.Format("{0}: {1}", "SafeName", parameters.SafeName));
            LogWrite(string.Format("{0}: {1}", "FolderName", parameters.FolderName));
            LogWrite(string.Format("{0}: {1}", "ObjectName", parameters.ObjectName));
            LogWrite(string.Format("{0}: {1}", "MachineAddress", parameters.MachineAddress));
            LogWrite(string.Format("{0}: {1}", "TransparentMachineAddress", parameters.TransparentMachineAddress));
            LogWrite(string.Format("{0}: {1}", "UserName", parameters.UserName));
            LogWrite(string.Format("{0}: {1}", "PolicyId", parameters.PolicyId));
            LogWrite(string.Format("{0}: {1}", "RequestingUser", parameters.RequestingUser));
            LogWrite(string.Format("{0}: {1}", "RequestingUserFirstName", parameters.RequestingUserFirstName));
            LogWrite(string.Format("{0}: {1}", "RequestingUserSurName", parameters.RequestingUserSurname));
            LogWrite(string.Format("{0}: {1}", "BusinessEmail", parameters.RequestingUserEmail));
            LogWrite(string.Format("{0}: {1}", "ProvidedReason", parameters.ProvidedReason));
            LogWrite(string.Format("{0}: {1}", "SystemName", parameters.SystemName));
            LogWrite(string.Format("{0}: {1}", "DualControl", parameters.DualControl));
            LogWrite(string.Format("{0}: {1}", "DualControlRequestConfirmed", parameters.DualControlRequestConfirmed));

            LogWrite("[ Fetching ticketing parameter -> Additonal Properties ] ");
            foreach (var item in parameters.TicketingConnectionAccount.Properties)
            {
                if (item.Key == "LastFailDate" || item.Key == "LastSuccessChange" || item.Key == "LastSuccessReconciliation")
                {
                    LogWrite(string.Format("{0}: {1}", item.Key, UnixTimeStampToDateTime(item.Value)));
                }
                else
                {
                    LogWrite(string.Format("{0}: {1}", item.Key, item.Value));
                }

            }
            #endregion

            //#region Create Ticket  - not using

            /*
			//if matching createINC by pass code, create inc ticket
			LogWrite("Checking to create ticket...");
			switch (IsValueEmpty(createServiceNowIncValidationCode))
			{
				case false:
					bool ChCreateInc = Regex.IsMatch(ticketingID, createServiceNowIncValidationCode.Trim().ToUpper());
					if (ChCreateInc == true)
					{
						LogWrite("Entering Function CreateTicketIdUsingTicketingSystem()");
						ticketingID = null;
						ticketingID = CreateTicketIdUsingTicketingSystem();

						switch (IsValueEmpty(ticketingID))
						{
							case true:
								ticketingOutput.UserMessage = errorMessage + " TicketID failed to create.";
								ticketingOutput.TicketAuditOutput = auditMessage + " TicketID failed to create.";
								LogWrite(ticketingOutput.UserMessage);
								LogWrite(ticketingOutput.TicketAuditOutput);
								CsvWrite("", "Failed to Create");
								LogWrite("Process ended...");
								return false;
							case false:
								ticketingOutput.TicketId = ticketingID;
								ticketingOutput.TicketAuditOutput = " " + auditMessage + ticketingID + " created successfully.";
								LogWrite("TicketId: " + ticketingID);
								LogWrite(ticketingOutput.TicketAuditOutput);
								CsvWrite(ticketingID, "Created Successfully");
								LogWrite("Process ended...");
								return true;
						}
					}
					break;
			}
			*/
            //#endregion

            #region Validate Ticket

            #region check emergencyMode
            //if matching bypass code, return true
            LogWrite("[ Checking TicketID matched BypassID ]");
            switch (IsValueEmpty(bypassServiceNowValidationCode))
            {
                case false:
                    emergencyMode = Regex.IsMatch(ticketingID, bypassServiceNowValidationCode);
                    auditMessage += " Emergency=" + emergencyMode + " | ";
                    if (emergencyMode == true)
                    {
                        auditMessage += "Ticket validated successfully.";
                        ticketingOutput.TicketAuditOutput = string.Format("{0},{1}", ticketingID, auditMessage);
                        LogWrite(ticketingOutput.TicketAuditOutput);
                        CsvWrite(ticketingID, "Validated Successfully");
                        LogWrite("[ Process ended ]");
                        return true;
                    }
                    break;
                case true:
                    errorMessage = "Please configure bypassServiceNowValidationCode.";
                    return false;
            }
            #endregion

            #region check ticket format
            //if ticket format is incorrect, return false
            LogWrite("Checking TicketID is in correct format...");
            switch (IsValueEmpty(allowTicketFormatRegex))
            {
                case false:
                    bool ChTicketFormatResult = Regex.IsMatch(ticketingID, allowTicketFormatRegex);
                    if (ChTicketFormatResult == false)
                    {
                        errorMessage = string.Format("[{0} - {1}] {2}", ticketingSys, ticketingID, msgInvalidTicketFormat);
                        ticketingOutput.UserMessage = errorMessage;
                        LogWrite(ticketingOutput.UserMessage);
                        CsvWrite(ticketingID, "Failed to validate");
                        LogWrite("Process ended...");
                        return bValid;
                    }
                    break;
                case true:
                    errorMessage = "Please configure allowTicketFormatRegex.";
                    return false;
            }
            #endregion

            #region check connection to ServiceNow
            switch (connectionAccount == null)
            {
                case true:
                    ticketingOutput.UserMessage = "No ticketing system login account was specified";
                    LogWrite(ticketingOutput.UserMessage);
                    LogWrite("[ Process ended ]");
                    return bValid;
                case false:
                    switch (chkLogonToTicketingSystem)
                    {
                        case true:
                            //Check Firewall Port
                            LogWrite("[ Checking Firewall port 443 to " + ServiceNowlogonAddress + " ]");
                            bool isPortOpened = TestTcpConnection();
                            LogWrite("Firewall Port 443 Connectivity to " + ServiceNowlogonAddress + " ] : " + isPortOpened);
                            if (isPortOpened == false)
                            {
                                ticketingOutput.UserMessage = "Firewall Port 443 Connectivity to " + ServiceNowlogonAddress + " ] : " + isPortOpened;
                                LogWrite(errorMessage);
                                LogWrite("[ Process ended ]");
                                return bValid;
                            }

                            //Check API Connectivity
                            LogWrite("[ Checking API Connectivity to " + ServiceNowlogonAddress + " ]");
                            bool isConnectedToServiceNow = LogonToTicketingSystem();
                            if (isConnectedToServiceNow == false)
                            {
                                ticketingOutput.UserMessage = errorMessage;
                                LogWrite(errorMessage);
                                LogWrite("[ Process ended ]");
                                return bValid;
                            }
                            LogWrite("API Connectivity to ServiceNow: " + isConnectedToServiceNow);
                            break;
                        case false:
                            LogWrite("API Connectivity to ServiceNow " + "Not configured to check");
                            break;
                    }
                    break;
            }
            #endregion

            #region check ticket validity
            LogWrite("[ Checking TicketID validity ]");
            bValid = CheckTicketIdValidity(ticketingID);
            #endregion

            #region post-validation
            switch (bValid)
            {
                case false:
                    auditMessage += " TicketID validation failed.";
                    ticketingOutput.UserMessage = errorMessage;
                    ticketingOutput.TicketAuditOutput = auditMessage;
                    LogWrite("Error: " + errorMessage);
                    LogWrite("Audit: " + auditMessage);
                    CsvWrite(ticketingID, "Failed to Validate");
                    break;
                case true:
                    auditMessage += " TicketID validated successfully.";
                    ticketingOutput.TicketId = ticketingID;
                    ticketingOutput.TicketAuditOutput = auditMessage;
                    if (ticketStartTime != DateTime.MinValue && ticketEndTime != DateTime.MinValue)
                    {
                        ticketingOutput.RequestStartDate = ticketStartTime;
                        ticketingOutput.RequestEndDate = ticketEndTime;
                    }
                    LogWrite("TicketId: " + ticketingID);
                    LogWrite("Audit: " + auditMessage);
                    CsvWrite(ticketingID, "Validated Successfully");

                    //Comment on ServiceNow WorkNotes 
                    LogWrite("[ Writing comment ] - TicketID: " + ticketingID);
                    var comment = new ServiceNowComment();
                    comment.AddCommentLine("Reason: " + cybrReason);
                    comment.AddCommentLine("Requesting User: " + cybrRequesterName);
                    comment.AddCommentLine("Requesting User ADID: " + cybrRequestingUser);
                    comment.AddCommentLine("Requesting User Email: " + cybrEmail);
                    comment.AddCommentLine("Device Address: " + GetConnectionAddress());
                    comment.AddCommentLine("Safe: " + cybrSafeName);
                    comment.AddCommentLine("Object: " + cybrObjectName);
                    comment.AddCommentLine("Account: " + cybrUsername);
                    comment.AddCommentLine("Policy: " + cybrPolicy);
                    //Additional Parameter
                    OutputToCommentIfNotEmpty(comment, "Hostname", cybrHostname);
                    OutputToCommentIfNotEmpty(comment, "Database", cybrDatabase);
                    OutputToCommentIfNotEmpty(comment, "Port", cybrPort);
                    OutputToCommentIfNotEmpty(comment, "Dual Control", cybrDualControl.ToString());
                    OutputToCommentIfNotEmpty(comment, "Dual Control Request Confirmed", cybrDualControlRequestConfirmed.ToString());

                    //Call Api to ServiceNow
                    var CommentToServiceNow = new ServiceNowApi()
                    {
                        url = "https://" + ServiceNowlogonAddress + "/rest/servicedeskapi/request/" + ticketingID + "/comment",
                        method = "post",
                        username = ServiceNowlogonUsername,
                        password = ServiceNowlogonPassword,
                        timeout = ServiceNowApiCall_Timeout,
                        body = JsonConvert.SerializeObject(comment)
                    };
                    bool IsCommentSuccessul = (int)CommentToServiceNow.Call().StatusCode == 201;
                    LogWrite(string.Format("Comment On TicketID: {0} Status: {1}", ticketingID, IsCommentSuccessul));
                    break;
            }
            #endregion

            LogWrite("[ Process ended ]");
            return bValid;
            #endregion
        }

        //If value not empty, write to comment object
        private void OutputToCommentIfNotEmpty(ServiceNowComment comment, string key, string value)
        {
            switch (IsValueEmpty(value))
            {
                case false:
                    comment.AddCommentLine(string.Format("{0}: {1}", key, value));
                    break;
            }
        }

        //Convert Unix Tiem Stamp to DateTime
        private static string UnixTimeStampToDateTime(string unixTimeStamp)
        {
            //Convert string to Double
            Double.TryParse(unixTimeStamp, out double unixTimeStampDouble);

            // Unix timestamp is seconds past epoch
            DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTime = dateTime.AddSeconds(unixTimeStampDouble).ToLocalTime();
            return dateTime.ToString();
        }

        #endregion

        // #region Private Function CreateTicketIdUsingTicketingSystem - return ticket ID if ticket successfully created, else return null

        // private string CreateTicketIdUsingTicketingSystem() {

        // 	LogWrite("Entered CreateTicketIdUsingTicketingSystem()");
        // 	//If there is no tower, cannot create incident ticket.
        // 	switch (IsValueEmpty(cybrTower))
        // 	{
        // 		case true:
        // 			errorMessage += " You are not authorized to create Incident ticket in PAM Portal. Please check with PAM Team.";
        // 			return null;
        // 	}

        // 	//Get address
        // 	string address = GetConnectionAddress();
        // 	LogWrite("address: " + address);

        // 	//Query Cmdb
        // 	LogWrite("Querying Cmdb...");
        // 	var json = new CmdbQueryHost(address);
        // 	var QueryToCmbd = new ServiceNowApi()
        // 	{
        // 		url = "https://" + ServiceNowlogonAddress + "/rest/insight/1.0/object/navlist/iql",
        // 		method = "post",
        // 		username = ServiceNowlogonUsername,
        // 		password = ServiceNowlogonPassword,
        // 		body = JsonConvert.SerializeObject(json)
        // 	};

        // 	//Capture response
        // 	var CmdbResponse = new CmdbQueryResponse(QueryToCmbd.Call());

        // 	//Get ConfigItemId
        // 	configItemID = CmdbResponse.ConfigItem_ID;
        // 	LogWrite("configItemID: " + configItemID);
        // 	if (string.IsNullOrEmpty(configItemID) == true)
        // 	{
        // 		errorMessage += "Failed to get server ID from CMDB.";
        // 		return null;
        // 	}

        // 	//Create Incident Ticket Object
        // 	LogWrite("Creating Incident ticket...");
        // 	var incidentTicket = new Ticket("INC");

        // 	//Incident ticket properties
        // 	incidentTicket.AddReason(cybrReason);
        // 	incidentTicket.AddAssignee(cybrRequestingUser);
        // 	incidentTicket.AddCI(configItemID);
        // 	incidentTicket.AddTower(cybrTower);
        // 	incidentTicket.AppendDescription("Requesting User: " + cybrRequesterName);
        // 	incidentTicket.AppendDescription("Requesting User ADID: " + cybrRequestingUser);
        // 	incidentTicket.AppendDescription("Requesting User Email: " + cybrEmail);
        // 	incidentTicket.AppendDescription("Device Address: " + address);
        // 	incidentTicket.AppendDescription("Safe: " + cybrSafeName);
        // 	incidentTicket.AppendDescription("Object: " + cybrObjectName);
        // 	incidentTicket.AppendDescription("Account: " + cybrUsername);
        // 	incidentTicket.AppendDescription("Policy: " + cybrPolicy);
        // 	OutputToIncDescIfNotEmpty(incidentTicket, "Hostname", cybrHostname);
        // 	OutputToIncDescIfNotEmpty(incidentTicket, "Database", cybrDatabase);
        // 	OutputToIncDescIfNotEmpty(incidentTicket, "Port", cybrPort);
        // 	OutputToIncDescIfNotEmpty(incidentTicket, "Dual Control", cybrDualControl.ToString());
        // 	OutputToIncDescIfNotEmpty(incidentTicket, "Dual Control Request Confirmed", cybrDualControlRequestConfirmed.ToString());

        // 	//Send to ServiceNow
        // 	LogWrite("Sending Api to ServiceNow...");
        // 	var LogonToServiceNow = new ServiceNowApi()
        // 	{
        // 		url = "https://" + ServiceNowlogonAddress + "/rest/api/2/issue/",
        // 		method = "post",
        // 		username = ServiceNowlogonUsername,
        // 		password = ServiceNowlogonPassword,
        // 		body = JsonConvert.SerializeObject(incidentTicket)
        // 	};

        // 	//Capture response
        // 	var response = LogonToServiceNow.Call();
        // 	var responseHandle = new ServiceNowCreateTicketResponse(response);

        // 	//Get ticketID
        // 	switch (responseHandle.StatusCode)
        // 	{
        // 		case 201:
        // 			return responseHandle.GetTicketID();
        // 		default:
        // 			errorMessage = "API response status code is not 201(created). " + responseHandle.GetError();
        // 			return null;
        // 	}			
        // }

        // //If value not empty, write to comment object
        // private void OutputToIncDescIfNotEmpty(Ticket incidentTicket, string key, string value)
        // {
        // 	switch (IsValueEmpty(value))
        // 	{
        // 		case false:
        // 			incidentTicket.AppendDescription(string.Format("{0}: {1}", key, value));
        // 			break;
        // 	}
        // }
        // #endregion

        #region Private Function CheckTicketIdValidity - return TRUE if ticket is valid
        private bool CheckTicketIdValidity(string ticketID)
        {
            LogWrite("[ Entered CheckTicketIdValidity() ]");

            //Checking bypassValidateTimeMode;
            bypassValidateTimeMode = ticketID.Contains(bypassServiceNowValidateTimeStampCode);
            if (bypassValidateTimeMode == true)
            {
                enChkTime = false;
                auditMessage += " bypassValidateTimeMode= " + bypassValidateTimeMode + " | ";

                //Extract TicketID
                ticketID = ticketID.Replace(bypassServiceNowValidateTimeStampCode, "").Trim();
                ticketingID = ticketID;
            }
            LogWrite("bypassValidateTimeMode: " + bypassValidateTimeMode);
            LogWrite("enChkTime: " + enChkTime);

            //Ticket Type - CTASK/REQ/RITM/PRB/PTASK/SCTASK/INC/CHG/INTSK
            string ticketType = ticketID.Split('|')[0].Trim().ToUpper();
            string ticketCategory = string.Empty;
            switch (ticketType)
            {
                case "CTASK":
                    ticketCategory = "CTASK";
                    break;
                case "REQ":
                    ticketCategory = "REQ";
                    break;
                case "RITM":
                    ticketCategory = "RITM";
                    break;
                case "PRB":
                    ticketCategory = "PRB";
                    break;
                case "PTASK":
                    ticketCategory = "PTASK";
                    break;
                case "SCTASK":
                    ticketCategory = "SCTASK";
                    break;
                case "TASK":
                    ticketCategory = "TASK";
                    break;
                case "INC":
                    ticketCategory = "INC";
                    break;
                case "INTSK":
                    ticketCategory = "INTSK";
                    break;
                case "CHG":
                    ticketCategory = "CHG";
                    break;

            }

            LogWrite("ticketType(extracted from ticket ID): " + ticketType);
            LogWrite("ticketCategory: " + ticketCategory);

            LogWrite("Sending Api to ServiceNow");
            var QueryToServiceNow = new ServiceNowApi()
            {
                url = "https://" + ServiceNowlogonAddress + "/rest/api/2/issue/" + ticketID,
                method = "get",
                username = ServiceNowlogonUsername,
                password = ServiceNowlogonPassword,
                timeout = ServiceNowApiCall_Timeout
            };

            var response = QueryToServiceNow.Call();

            switch (response.IsSuccessful)
            {
                case true:
                    var ServiceNowQuery = new ServiceNowQueryResponse(response);

                    bool ChkCIResult;
                    bool ChkTimeResult;
                    bool ChkImplementerResult;
                    bool ChkCurrentTicketStatus;

                    //Ticket Type - CTASK/REQ/RITM/PRB/PTASK/SCTASK/INC/CHG/INTSK
                    switch (ticketCategory)
                    {
                        //Change Ticket
                        case "CHG":
                            enChkCI = enChkCI_CHG;
                            ChkTimeResult = ValidateTime(ServiceNowQuery);
                            ChkCIResult = ValidateCI(ServiceNowQuery);
                            ChkImplementerResult = ValidateAssignee(ServiceNowQuery);
                            ChkCurrentTicketStatus = ValidateTicketStatus(ServiceNowQuery, ticketCategory);
                            break;

                        //Change Task Ticket
                        case "CTASK":
                            enChkCI = enChkCI_CTASK;
                            ChkTimeResult = true;
                            ChkCIResult = ValidateCI(ServiceNowQuery);
                            ChkImplementerResult = ValidateAssignee(ServiceNowQuery);
                            ChkCurrentTicketStatus = ValidateTicketStatus(ServiceNowQuery, ticketCategory);
                            break;

                        //Incident Ticket
                        case "INC":
                            enChkCI = enChkCI_INC;
                            ChkTimeResult = true;
                            ChkCIResult = ValidateCI(ServiceNowQuery);
                            ChkImplementerResult = ValidateAssignee(ServiceNowQuery);
                            ChkCurrentTicketStatus = ValidateTicketStatus(ServiceNowQuery, ticketCategory);
                            break;

                        //Problem Ticket
                        case "PRB":
                            ChkTimeResult = true;
                            ChkCIResult = ValidateCI(ServiceNowQuery);
                            ChkImplementerResult = ValidateAssignee(ServiceNowQuery);
                            ChkCurrentTicketStatus = ValidateTicketStatus(ServiceNowQuery, ticketCategory);
                            break;

                        //Requeste Ticket
                        case "REQ":
                            enChkCI = enChkCI_REQ;
                            ChkTimeResult = ValidateTime(ServiceNowQuery);
                            ChkCIResult = ValidateCI(ServiceNowQuery);
                            ChkImplementerResult = ValidateAssignee(ServiceNowQuery);
                            ChkCurrentTicketStatus = ValidateTicketStatus(ServiceNowQuery, ticketCategory);
                            break;

                        //Requested Item Ticket
                        case "RITM":
                            enChkCI = enChkCI_RITM;
                            ChkTimeResult = true;
                            ChkCIResult = ValidateCI(ServiceNowQuery);
                            ChkImplementerResult = ValidateAssignee(ServiceNowQuery);
                            ChkCurrentTicketStatus = ValidateTicketStatus(ServiceNowQuery, ticketCategory);
                            break;

                        //Problem Task Ticket
                        case "PTASK":
                            enChkCI = enChkCI_PTASK;  //review this
                            ChkTimeResult = true;
                            ChkCIResult = ValidateCI(ServiceNowQuery);
                            ChkImplementerResult = ValidateAssignee(ServiceNowQuery);
                            ChkCurrentTicketStatus = ValidateTicketStatus(ServiceNowQuery, ticketCategory);
                            break;

                        //Service Catalog Task Ticket
                        case "SCTASK":
                            ChkTimeResult = true;
                            ChkCIResult = ValidateCI(ServiceNowQuery);
                            ChkImplementerResult = ValidateAssignee(ServiceNowQuery);
                            ChkCurrentTicketStatus = ValidateTicketStatus(ServiceNowQuery, ticketCategory);
                            break;

                        //Incident Task Ticket
                        case "INTSK":
                            ChkTimeResult = true;
                            ChkCIResult = ValidateCI(ServiceNowQuery);
                            ChkImplementerResult = ValidateAssignee(ServiceNowQuery);
                            ChkCurrentTicketStatus = ValidateTicketStatus(ServiceNowQuery, ticketCategory);
                            break;

                        default:
                            errorMessage += "Ticket was not configured to be validated.";
                            return false;
                    }
                    return (ChkTimeResult && ChkCIResult && ChkImplementerResult && ChkCurrentTicketStatus);

                case false:
                    errorMessage = string.Format("[{0} - {1}] {2}", ticketingSys, ticketingID, msgInvalidTicket);
                    break;
            }

            errorMessage = string.Format("[{0} - {1}] {2}", ticketingSys, ticketingID, msgInvalidTicket);
            LogWrite(errorMessage);
            return false;
        }

        private bool ValidateTime(ServiceNowQueryResponse ServiceNowQuery)
        {
            bool result = false;

            if (enChkTime == false)
            {
                return true;
            }
            if (enChkTime == true)
            {
                if (string.IsNullOrEmpty(ServiceNowApiKey_StartTime) == false && string.IsNullOrEmpty(ServiceNowApiKey_EndTime) == false)
                {
                    LogWrite("Checking ticket time Validity...");

                    //Get StartTime, EndTime
                    string strStartTime = ServiceNowQuery.GetCustomField(ServiceNowApiKey_StartTime);
                    string strEndTime = ServiceNowQuery.GetCustomField(ServiceNowApiKey_EndTime);
                    result = Timecheck(strStartTime, strEndTime);
                    LogWrite("Ticket Start Time: " + ticketStartTime);
                    LogWrite("Ticket End Time: " + ticketEndTime);
                    if (result == false)
                    {
                        errorMessage = string.Format("[{0} - {1}] Access only allowed from {2} to {3}.", ticketingSys, ticketingID, ticketStartTime, ticketEndTime);
                    }
                }
                else
                {
                    errorMessage = string.Format("ServiceNowApiKey_StartTime or ServiceNowApiKey_EndTime is null. Please check PAM Option.");
                }
            }

            return result;
        }

        private bool ValidateCI(ServiceNowQueryResponse ServiceNowQuery)
        {
            bool result = false;

            if (enChkCI == false)
            {
                return true;
            }
            string deviceAddress = string.Empty;
            if (enChkCI == true)
            {
                string connectionAddress = GetConnectionAddress();
                LogWrite("connectionAddress: " + connectionAddress);

                //If connectionAddress is *, return True
                if (connectionAddress == "*")
                {
                    return true;
                }

                if (string.IsNullOrEmpty(ServiceNowApiKey_CI) == true)
                {
                    errorMessage = string.Format("ServiceNowApiKey_CI is null. Please check PAM Option.");
                    return false;
                }

                //Query Cmdb as hostname
                var json = new CmdbQueryHost(connectionAddress);
                var QueryToCmbd = new ServiceNowApi()
                {
                    url = "https://" + ServiceNowlogonAddress + "/rest/insight/1.0/object/navlist/iql",
                    method = "post",
                    username = ServiceNowlogonUsername,
                    password = ServiceNowlogonPassword,
                    timeout = ServiceNowApiCall_Timeout,
                    body = JsonConvert.SerializeObject(json)
                };
                var CmdbResponse = new CmdbQueryResponse(QueryToCmbd.Call());

                //Get ConfigItemId
                configItemID = CmdbResponse.ConfigItem_ID;
                LogWrite("configItemID - [query as host]: " + configItemID);

                //If ConfigItemId is empty, query using network device format again.
                if (string.IsNullOrEmpty(configItemID))
                {
                    //Query Cmdb as network device
                    var json2 = new CmdbQueryNetworkDevice(connectionAddress);
                    var QueryToCmbd2 = new ServiceNowApi()
                    {
                        url = "https://" + ServiceNowlogonAddress + "/rest/insight/1.0/object/navlist/iql",
                        method = "post",
                        username = ServiceNowlogonUsername,
                        password = ServiceNowlogonPassword,
                        timeout = ServiceNowApiCall_Timeout,
                        body = JsonConvert.SerializeObject(json2)
                    };
                    var CmdbResponse2 = new CmdbQueryResponse(QueryToCmbd2.Call());

                    //Get ConfigItemId
                    configItemID = CmdbResponse2.ConfigItem_ID;
                    LogWrite("configItemID - [query as network device]: " + configItemID);

                }

                //Validate Ticket CI
                result = ServiceNowQuery.ValidateCI(configItemID, ServiceNowApiKey_CI);

                if (result == false)
                {
                    errorMessage = string.Format("[{0} - {1}] Machine {2} is not part of ticket's configuration items.", ticketingSys, ticketingID, cybrTransparentMachineAddress);
                }
            }

            return result;
        }

        private bool ValidateAssignee(ServiceNowQueryResponse ServiceNowQuery)
        {
            bool result = false;

            if (enChkImplementer == false)
            {
                return true;
            }
            if (enChkImplementer == true)
            {
                //Get assignee
                string strAssignee = ServiceNowQuery.GetAssignee();
                LogWrite("Ticket Assignee: " + strAssignee);
                if (strAssignee == null)
                {
                    errorMessage = string.Format("[{0} - {1}] {2} is not ticket assignee", ticketingSys, ticketingID, cybrRequestingUser.ToLower());
                    return false;
                }

                result = strAssignee.Trim().ToUpper() == cybrRequestingUser;

                if (result == true)
                {
                    auditMessage += "TicketAssignee= " + strAssignee + " | ";
                }

                if (result == false)
                {
                    errorMessage = string.Format("[{0} - {1}] {2} is not ticket assignee.", ticketingSys, ticketingID, cybrRequestingUser.ToLower());
                }
            }

            return result;
        }

        private bool ValidateTicketStatus(ServiceNowQueryResponse ServiceNowQuery, string TicketCategory)
        {
            string allowedTicketStatus = string.Empty;
            bool result = false;

            switch (TicketCategory)
            {
                case "CHG":
                    allowedTicketStatus = AllowedChangeTicketStates;
                    break;

                case "CTASK":
                    allowedTicketStatus = AllowedChangeTaskTicketStates;
                    break;

                case "INC":
                    allowedTicketStatus = allowedIncidentTicketStatus;
                    break;

                case "REQ":
                    allowedTicketStatus = AllowedRequestTicketStates;
                    break;

                case "RITM":
                    allowedTicketStatus = AllowedRequestedItemTicketStates;
                    break;

                case "SCTASK":
                    allowedTicketStatus = AllowedServiceCatalogTaskTicketStates;
                    break;

                case "PTASK":
                    allowedTicketStatus = AllowedProblemTaskTicketStates;
                    break;

                case "PRB":
                    allowedTicketStatus = AllowedProblemTicketStates;
                    break;

                case "TASK":
                    allowedTicketStatus = AllowedCatalogTaskTicketStates;
                    break;

            }

            if (IsValueEmpty(allowedTicketStatus) == true)
            {
                errorMessage += "allowTicketStatus is null. Please contact PAM administrator."; // update to use PVWA UI error msg
                return false;
            }

            //Validate status
            string strCurrentTicketStatus = ServiceNowQuery.GetStatus();
            LogWrite("Ticket Status: " + strCurrentTicketStatus);
            result = Regex.IsMatch(strCurrentTicketStatus, allowedTicketStatus);
            if (result == false)
            {
                errorMessage = string.Format("[{0} - {1}] Current ticket Status: {2}, Allow Ticket Status: {3}", ticketingSys, ticketingID, strCurrentTicketStatus, allowedTicketStatus);
            }

            return result;

        }

        private string GetConnectionAddress()
        {
            if (cybrTransparentMachineAddress != null)
            {
                return cybrTransparentMachineAddress;
            }

            if (cybrMachineAddress != null)
            {
                return cybrMachineAddress;
            }
            return null;
        }

        private bool Timecheck(string timeStart, string timeEnd)
        {

            if (timeStart == null || timeEnd == null)
            {
                errorMessage = "Start time or end time cannot be null.";
                return false;
            }

            //Sample Return From RestSharp - 01/26/2021 13:00:00 - String
            int yearStart = int.Parse(timeStart.Substring(6, 4));
            int yearEnd = int.Parse(timeEnd.Substring(6, 4));
            int monthStart = int.Parse(timeStart.Substring(0, 2));
            int monthEnd = int.Parse(timeEnd.Substring(0, 2));
            int dayStart = int.Parse(timeStart.Substring(3, 2));
            int dayEnd = int.Parse(timeEnd.Substring(3, 2));
            int hourStart = int.Parse(timeStart.Substring(11, 2));
            int hourEnd = int.Parse(timeEnd.Substring(11, 2));
            int minStart = int.Parse(timeStart.Substring(14, 2));
            int minEnd = int.Parse(timeEnd.Substring(14, 2));
            int secStart = int.Parse(timeStart.Substring(17, 2));
            int secEnd = int.Parse(timeEnd.Substring(17, 2));

            ticketStartTime = new DateTime(yearStart, monthStart, dayStart, hourStart, minStart, secStart);
            ticketEndTime = new DateTime(yearEnd, monthEnd, dayEnd, hourEnd, minEnd, secEnd);
            DateTime now = DateTime.Now;

            return ((now > ticketStartTime) && (now < ticketEndTime));
        }

        #endregion

        #region Private Function LogonToTicketingSystem - return TRUE if able to connect to Ticketing System
        private bool LogonToTicketingSystem()
        {

            var LogonToServiceNow = new ServiceNowApi()
            {
                url = "https://" + ServiceNowlogonAddress,
                method = "get",
                username = ServiceNowlogonUsername,
                password = ServiceNowlogonPassword,
                timeout = ServiceNowApiCall_Timeout
            };

            var response = LogonToServiceNow.Call();

            if (response.IsSuccessful)
            {
                return true;
            }
            else
            {
                errorMessage = response.ErrorMessage + " " + response.ErrorException;
            }

            errorMessage = errorMessage + " " + msgConnectionError + " " + "Unable to connect to " + ServiceNowlogonAddress + " ";
            return false;
        }

        private bool TestTcpConnection()
        {
            using (TcpClient tcpClient = new TcpClient())
            {
                try
                {
                    tcpClient.Connect(ServiceNowlogonAddress, 443);
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }
        }
        #endregion

        #region Private Function ParseXmlParameters - Capture Ticketing Parameters from PVConfig.xml
        private void ParseXmlParameters(XmlNode xmlParameters)
        {
            //Fetch ticketing parameters from PVWA
            checkParameters = xmlParameters.InnerXml;

            //Allow Ticket Status
            allowedChangeTicketStatus = ExtractValueFromXML(checkParameters, "allowedChangeTicketStatus");
            allowedIncidentTicketStatus = ExtractValueFromXML(checkParameters, "allowedIncidentTicketStatus");
            allowedProblemTicketStatus = ExtractValueFromXML(checkParameters, "allowedProblemTicketStatus");

            //Allow Ticket States			
            AllowedChangeTicketStates = ExtractValueFromXML(checkParameters, "AllowedChangeTicketStates");
            AllowedChangeTaskTicketStates = ExtractValueFromXML(checkParameters, "AllowedChangeTaskTicketStates");
            allowedIncidentTicketStates = ExtractValueFromXML(checkParameters, "allowedIncidentTicketStates");
            AllowedRequestTicketStates = ExtractValueFromXML(checkParameters, "AllowedRequestTicketStates");
            AllowedRequestedItemTicketStates = ExtractValueFromXML(checkParameters, "AllowedRequestedItemTicketStates");
            AllowedServiceCatalogTaskTicketStates = ExtractValueFromXML(checkParameters, "AllowedServiceCatalogTaskTicketStates");
            AllowedProblemTaskTicketStates = ExtractValueFromXML(checkParameters, "AllowedProblemTaskTicketStates");
            AllowedProblemTicketStates = ExtractValueFromXML(checkParameters, "AllowedProblemTicketStates");
            AllowedCatalogTaskTicketStates = ExtractValueFromXML(checkParameters, "AllowedCatalogTaskTicketStates");

            //Allow Ticket Format Regex
            allowTicketFormatRegex = ExtractValueFromXML(checkParameters, "allowTicketFormatRegex");

            //Error Message
            msgInvalidTicket = ExtractValueFromXML(checkParameters, "msgInvalidTicket");
            msgInvalidTicketFormat = ExtractValueFromXML(checkParameters, "msgInvalidTicketFormat");
            msgInvalidTicketStatus = ExtractValueFromXML(checkParameters, "msgInvalidTicketStatus");
            msgConnectionError = ExtractValueFromXML(checkParameters, "msgConnectionError");
            msgInvalidAccessTime = ExtractValueFromXML(checkParameters, "msgInvalidAccessTime");
            msgInvalidMachine = ExtractValueFromXML(checkParameters, "msgInvalidMachine");
            msgInvalidImplementer = ExtractValueFromXML(checkParameters, "msgInvalidImplementer");

            //chkLogonToTicketingSystem
            chkLogonToTicketingSystem = ConvertToBool(ExtractValueFromXML(checkParameters, "chkLogonToTicketingSystem"));

            //validateServiceNowTimeStamp
            enChkTime = ConvertToBool(ExtractValueFromXML(checkParameters, "validateServiceNowTimeStamp"));

            //validateServiceNowCI
            enChkCI_CHG = ConvertToBool(ExtractValueFromXML(checkParameters, "validateServiceNowCIforCHG"));
            enChkCI_INC = ConvertToBool(ExtractValueFromXML(checkParameters, "validateServiceNowCIforINC"));
            enChkCI_RITM = ConvertToBool(ExtractValueFromXML(checkParameters, "validateServiceNowCIforRITM"));

            //validateServiceNowImplementer
            enChkImplementer = ConvertToBool(ExtractValueFromXML(checkParameters, "validateServiceNowImplementer"));

            //bypass code
            bypassServiceNowValidationCode = ExtractValueFromXML(checkParameters, "bypassServiceNowValidationCode").Trim().ToUpper();
            bypassServiceNowValidateTimeStampCode = ExtractValueFromXML(checkParameters, "bypassServiceNowValidateTimeStampCode").Trim().ToUpper();

            //create ticket code
            //createServiceNowIncValidationCode			= ExtractValueFromXML(checkParameters, "createServiceNowIncValidationCode").Trim().ToUpper();

            //ServiceNow json key
            ServiceNowApiKey_CI = ExtractValueFromXML(checkParameters, "ServiceNowJsonKey_CI");
            ServiceNowApiKey_StartTime = ExtractValueFromXML(checkParameters, "ServiceNowJsonKey_StartTime");
            ServiceNowApiKey_EndTime = ExtractValueFromXML(checkParameters, "ServiceNowJsonKey_EndTime");

            //ServiceNow api call time out
            ServiceNowApiCall_Timeout = int.Parse(ExtractValueFromXML(checkParameters, "ServiceNowApiCall_Timeout"));

            //log
            logFilePath = ExtractValueFromXML(checkParameters, "logFilePath");

            // ServiceNow URL
            ServiceNowURL = ExtractValueFromXML(checkParameters, "ServiceNowURL");

            // OAuth URL
            OAuthURL = ExtractValueFromXML(checkParameters, "OAuthURL");

            //validate ticket ID's related CI
            validateconfigurationitem = ExtractValueFromXML(checkParameters, "validateconfigurationitem");

            //validate ticket ID's assigned to field
            validateassignedto = ExtractValueFromXML(checkParameters, "validateassignedto");

            //validate ticket ID's assignment group
            validateassignmentGroup = ExtractValueFromXML(checkParameters, "validateassignmentGroup");

            //Maintenance Mode enabled?
            MaintenanceModeEnabled = ExtractValueFromXML(checkParameters, "FailOpenEnabled");

            //AuditOnly Mode enabled?
            AuditOnlyMode = ExtractValueFromXML(checkParameters, "AuditOnlyMode");

            //Logging enabled?
            EnableLogging = ExtractValueFromXML(checkParameters, "EnableLogging");

            //CTASK Format
            ChangeTaskTicketFormat = ExtractValueFromXML(checkParameters, "ChangeTaskTicketFormat");

            //REQ Format
            RequestTicketFormat = ExtractValueFromXML(checkParameters, "RequestTicketFormat");

            //RITM Format
            RequestedItemTicketFormat = ExtractValueFromXML(checkParameters, "RequestedItemTicketFormat");

            //CTASK Format
            CatalogTaskTicketFormat = ExtractValueFromXML(checkParameters, "CatalogTaskTicketFormat");

            //PRB Format
            ProblemTicketFormat = ExtractValueFromXML(checkParameters, "ProblemTicketFormat");

            //PTASK Format
            ProblemTaskTicketFormat = ExtractValueFromXML(checkParameters, "ProblemTaskTicketFormat");

            //SCTASK Format
            ServiceCatalogTaskTicketFormat = ExtractValueFromXML(checkParameters, "ServiceCatalogTaskTicketFormat");

            //ServiceNowApiCallTimeout
            ServiceNowApiCallTimeout = ExtractValueFromXML(checkParameters, "ServiceNowApiCallTimeout");
        }

        private string ExtractValueFromXML(string checkParameters, string lookupValue)
        {
            string regexPattern = lookupValue + "\"" + " Value=\"(.*?)\"";
            Match strMatch = Regex.Match(checkParameters, regexPattern);
            string strResult = strMatch.Groups[1].Value.Trim();
            return strResult;
        }

        private bool ConvertToBool(string strParameter)
        {
            if (strParameter.Length > 0)
            {
                if (strParameter.Trim().ToLower().Equals("yes"))
                {
                    return true;
                }

                if (strParameter.Trim().ToLower().Equals("no"))
                {
                    return false;
                }
            }

            return false;
        }

        private bool IsValueEmpty(string value)
        {
            return string.IsNullOrEmpty(value);
        }

        //ValidateTicket - Obsolete Function  - Do not Remove - for backward compatibility only
        public bool ValidateTicket(IValidationParameters parameters, out string returnedMessage, out string returnedTicketId)
        {
            throw new NotImplementedException("Obsolete");
        }

        #endregion

        #region Private Function Log/Reporting
        private void LogWrite(string message)
        {
            //FilePath
            var logDirectory = Path.Combine(logFilePath, "Logs");
            if (Directory.Exists(logDirectory) == false)
                Directory.CreateDirectory(logDirectory);

            //FileName
            TextInfo myTI = new CultureInfo("en-US", false).TextInfo;

            var strToday = DateTime.Now.ToString("dd-MM-yyyy");
            //var strUser = cybrRequestingUser.ToLower();
            //var strName = myTI.ToTitleCase(cybrRequesterName);
            var strTicketingSys = myTI.ToTitleCase(ticketingSys);
            //var strTime = strToday + " " + "[ " + DateTime.Now.ToString("hh:mm:ss tt - fffff") + " ]";

            //var fileName = strTicketingSys + "_" + strUser + "_" + strName + "_" + strToday + ".log";

            //Log file name example: "ServiceNow_10272024.log"
            var fileName = strTicketingSys + "_" + strToday + ".log";

            var logFile = Path.Combine(logDirectory, fileName);

            var messageToAppend = strTime + " - " + message + Environment.NewLine;

            //Append Message
            File.AppendAllText(logFile, messageToAppend);
        }

        private void CsvWrite(string TicketID, string ValidationStatus)
        {
            //FilePath
            if (Directory.Exists(logFilePath) == false)
                Directory.CreateDirectory(logFilePath);

            //FileName
            var strMonthYear = DateTime.Now.ToString("Y");
            var csvFileName = "Statistic_" + strMonthYear + ".csv";
            var csvFile = Path.Combine(logFilePath, csvFileName);

            //File Exist
            if (File.Exists(csvFile) == false)
            {
                //TicketID, Validation Status, Reason, Safe, Object, Policy
                //Connection Address, Account, User, FirstName, Email
                //Dual Control, Dual Control Request Confirmed, emergencyMode
                var header = string.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16}"
                    , "Date", "Ticketing System", "TicketID", "Validation Status"
                    , "Provided Reason", "Safe", "Object", "Policy"
                    , "Connection Address", "Account", "User", "FirstName", "Email"
                    , "Dual Control", "Dual Control Request Confirmed", "Emergency Mode", "ByPassValidationTimeMode");
                header += Environment.NewLine;
                File.AppendAllText(csvFile, header);
            }

            //Append Message
            var messageToAppend = string.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16}"
                    , DateTime.Now.ToString(), ticketingSys, TicketID, ValidationStatus
                    , cybrReason.Replace(",", "|"), cybrSafeName, cybrObjectName, cybrPolicy
                    , GetConnectionAddress(), cybrUsername, cybrRequestingUser, cybrRequesterName, cybrEmail
                    , cybrDualControl.ToString(), cybrDualControlRequestConfirmed.ToString(), emergencyMode.ToString(), bypassValidateTimeMode.ToString());
            messageToAppend += Environment.NewLine;
            File.AppendAllText(csvFile, messageToAppend);
        }

        #endregion
    }

    #endregion



}
