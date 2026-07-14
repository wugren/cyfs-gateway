use buckyos_kit::get_buckyos_service_data_dir;
use cyfs_dns::CmdResolve;
use cyfs_gateway_lib::{ServerManager, get_external_commands};
use cyfs_process_chain::{COMMAND_PARSER_FACTORY, CommandHelpType, HookPointEnv};
use std::collections::HashSet;
use std::sync::Arc;

pub struct GatewayProcessChainDoc {
    env: HookPointEnv,
}

impl GatewayProcessChainDoc {
    pub fn new() -> Result<Self, String> {
        let data_dir = get_buckyos_service_data_dir("cyfs_gateway").join("process_chain_doc");
        let env = HookPointEnv::new("gateway-process-chain-doc", data_dir);
        Self::register_gateway_external_commands(&env)?;

        Ok(Self { env })
    }

    pub fn render_command_list(&self) -> String {
        let mut output = String::new();
        let mut groups: Vec<_> = COMMAND_PARSER_FACTORY
            .get_group_list()
            .into_iter()
            .collect();
        groups.sort_by_key(|(group, _)| group.as_str());

        output.push_str("Available process_chain commands:\n\n");
        for (group, cmds) in groups {
            output.push_str(&format!("[{}]\n", group.as_str()));
            output.push_str(&format!("{}\n\n", cmds.join(" ")));
        }

        let mut external_commands = self.env.parser_context().get_external_command_list();
        external_commands.sort();
        if !external_commands.is_empty() {
            output.push_str("[external]\n");
            output.push_str(&format!("{}\n", external_commands.join(" ")));
        } else {
            output.push_str("No external commands registered.\n");
        }

        output
    }

    pub fn render_command_help(&self, cmd: &str) -> String {
        if let Some(parser) = COMMAND_PARSER_FACTORY.get_parser(cmd) {
            return parser.help(cmd, CommandHelpType::Long);
        }

        if let Some(ext_cmd) = self.env.parser_context().get_external_command(cmd) {
            return ext_cmd.help(cmd, CommandHelpType::Long);
        }

        format!("No such process_chain command: {}", cmd)
    }

    pub fn render_all_docs(&self) -> String {
        let mut doc = String::new();
        let mut groups: Vec<_> = COMMAND_PARSER_FACTORY
            .get_group_list()
            .into_iter()
            .collect();
        groups.sort_by_key(|(group, _)| group.as_str());

        doc.push_str("# Command reference documentation\n\n");
        for (group, cmds) in groups {
            doc.push_str(&format!("## {}\n\n", group.as_str()));

            for cmd in cmds {
                if let Some(parser) = COMMAND_PARSER_FACTORY.get_parser(&cmd) {
                    let help = parser.help(&cmd, CommandHelpType::Long);
                    doc.push_str(&format!("### `{}`\n", cmd));
                    doc.push_str("```\n");
                    doc.push_str(help.trim());
                    doc.push_str("\n```\n\n");
                }
            }
        }

        let mut external_commands = self.env.parser_context().get_external_command_list();
        external_commands.sort();
        if !external_commands.is_empty() {
            doc.push_str("## External Commands\n\n");
            for cmd in external_commands {
                if let Some(ext_cmd) = self.env.parser_context().get_external_command(&cmd) {
                    let help = ext_cmd.help(&cmd, CommandHelpType::Long);
                    doc.push_str(&format!("### `{}`\n", cmd));
                    doc.push_str("```\n");
                    doc.push_str(help.trim());
                    doc.push_str("\n```\n\n");
                }
            }
        } else {
            doc.push_str("No external commands registered.\n");
        }

        doc
    }

    fn register_gateway_external_commands(env: &HookPointEnv) -> Result<(), String> {
        let server_manager = Arc::new(ServerManager::new());
        let mut registered = HashSet::new();
        for (name, cmd) in get_external_commands(Arc::downgrade(&server_manager)) {
            if !registered.insert(name.clone()) {
                continue;
            }
            env.register_external_command(&name, cmd)?;
        }
        let resolve_cmd = CmdResolve::new(Arc::downgrade(&server_manager));
        let resolve_name = resolve_cmd.name().to_string();
        env.register_external_command(resolve_name.as_str(), Arc::new(Box::new(resolve_cmd)))?;

        Ok(())
    }
}
