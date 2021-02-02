var MOB_Ada_Service = require("./meap_rm_mobile_adapter_service");
var RBT_Man_Context = require("./meap_rm_robot_manager_context");
function run(path, mod) {
    LOG1("[ROBM]INFO: ", "************************ROBOT MANAGER START**********************************");
    LOG1("[meap_rm_robot_manager][run] INFO: MEAP RM WORKER RUNNING ");
    var RMContext = new RBT_Man_Context.Context(path);
    RMContext.CopyRight = true;
    MOB_Ada_Service.Runner(RMContext);
}
exports.Runner = run;
exports.Context = RBT_Man_Context.Context;
