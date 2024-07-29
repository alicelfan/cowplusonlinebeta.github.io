console.log("flask branch")

let filterYearMin = 1000;
let filterYearMax = 3000;
let filterState1 = [];
let filterState2 = [];

function checkAgreements(){
	if((document.getElementById("privacy_policy").checked) && (document.getElementById("tos").checked)){
		document.getElementById("signupButtonSubmit").disabled = false;
	}
	else{
		document.getElementById("signupButtonSubmit").disabled = true;
	}
}

let dyadmonad = "monadic";
async function VarTable_S1(){
	var dataView;
	var grid;
	var data = [];
	variable_ids = await first_step_vars();
	function loadData() {
		data = [];
		count = variable_ids[0].length;
		// prepare the data
		for (var i = 0; i < count; i++) {
		  var d = (data[i] = {});
		  d["id"] = i;
		  d["var_name"] = variable_ids[0][i];
		  d["var_description"] = variable_ids[1][i];
		  d["var_dataset"] = variable_ids[3][i];
		  d["var_id"] = variable_ids[2][i];
		  d["var_type"] = variable_ids[4][i];
		  d["var_pvu"] = variable_ids[5][i];
		}
		dataView.setItems(data);
		return(data);
	}

	var checkboxSelector = new Slick.CheckboxSelectColumn({
		// cssClass: "slick-cell-checkboxsel"
	});

	var columns = [
		checkboxSelector.getColumnDefinition(),
		{id: "var_name", name: "var_name", field: "var_name", toolTip: "var_name", width: 100},
		{id: "var_description", name: "var_description", field: "var_description", toolTip: "var_description", width: 1000}
	];

	//displayColumns.unshift("id");
	var options = {
		enableCellNavigation: true,
        enableColumnReorder: false,
        explicitInitialization: true,
        editable: false,
		autosizeColsMode: true,
		fullWidthRows: true,
		forceFitColumns: true
	};
	
	function groupByPVUTypeDataset() {
		dataView.setGrouping([
			{
				getter: "var_pvu",
				formatter :function (g) {
					return g.value;
				},
				collapsed: false
			},
			{
				getter: "var_type",
				formatter :function (g) {
					return g.value;
				},
				collapsed: true
			},
			{
				getter: "var_dataset",
				formatter :function (g) {
					return g.value;
				},
				collapsed: true
			},
		]);
	}
	
	$(function () {
		var groupItemMetadataProvider = new Slick.Data.GroupItemMetadataProvider();
		dataView = new Slick.Data.DataView({
			groupItemMetadataProvider: groupItemMetadataProvider,
			inlineFilters: true
		});
		grid = new Slick.Grid("#grid_vars_first_step", dataView, columns, options);
        
		grid.registerPlugin(groupItemMetadataProvider);
		groupItemMetadataProvider.destroy();

		
		grid.setSelectionModel(new Slick.RowSelectionModel({selectActiveRow: false}));
		grid.registerPlugin(checkboxSelector);
		
		dataView.syncGridSelection(grid, true, true);

		dataView.onRowCountChanged.subscribe(function (e, args) {
		  grid.updateRowCount();
		  grid.render();
		});
		dataView.onRowsChanged.subscribe(function (e, args) {
			grid.invalidateRows(args.rows);
			grid.render();
		});
		grid.onSelectedRowsChanged.subscribe(function (evt, args) {
			grid.invalidateRows(args.rows);
			grid.render();
			
			variableChooser();
			datasetChooser();
		});

		dataView.beginUpdate();
		loadData();
		groupByPVUTypeDataset();
		grid.init();
		dataView.endUpdate()
		function variableChooser(){
			var selectedVars = [];
	
			selectedIndexes = grid.getSelectedRows();
			jQuery.each(selectedIndexes, function (index, value) {
				selectedVars.push(grid.getData().getItem(value)["var_name"]);
			});
			if(selectedVars.length > 0){
				document.getElementById("createButton").disabled = false;
			}
			else{
				document.getElementById("createButton").disabled = true;
			}	
			var xhr = new XMLHttpRequest();
			xhr.open("POST", "/variableChooser", true);
			xhr.setRequestHeader("Content-Type", "application/json");
			xhr.send(JSON.stringify({ array: selectedVars }));
			console.log("post vc:");
			console.log(selectedVars);
		}
		function datasetChooser(){
			let selectedDatasets = new Set();
	
			selectedIndexes = grid.getSelectedRows();
			jQuery.each(selectedIndexes, function (index, value) {
				selectedDatasets.add(grid.getData().getItem(value)["var_dataset"]);
				if(grid.getData().getItem(value)["var_type"] == "Country Year"){
					dyadmonad = "monadic";
				}
				else if (grid.getData().getItem(value)["var_type"] == "Dyad Year"){
					dyadmonad = "dyadic";
				}
			});
			console.log(selectedDatasets);
			let arrDatasets = Array.from(selectedDatasets);

			var xhr = new XMLHttpRequest();
			xhr.open("POST", "/datasetChooser", true);
			xhr.setRequestHeader("Content-Type", "application/json");
			xhr.send(JSON.stringify({ array: arrDatasets }));
			console.log("post dc:")
			console.log(arrDatasets)
		}
		
    });

}

async function VarTable_S2(){
	var dataView;
	var grid;
	var data = [];
	variable_ids = await second_step_vars();
	function loadData() {
		data = [];
		count = variable_ids[0].length;
		// prepare the data
		for (var i = 0; i < count; i++) {
		  var d = (data[i] = {});
		  d["id"] = i;
		  d["var_name"] = variable_ids[0][i];
		  d["var_description"] = variable_ids[1][i];
		  d["var_dataset"] = variable_ids[3][i];
		  d["var_id"] = variable_ids[2][i];
		  d["var_type"] = variable_ids[4][i];
		  d["var_pvu"] = variable_ids[5][i];
		}
		dataView.setItems(data);
		return(data);
	}

	var checkboxSelector = new Slick.CheckboxSelectColumn({
		// cssClass: "slick-cell-checkboxsel"
	});

	var columns = [
		checkboxSelector.getColumnDefinition(),
		{id: "var_name", name: "var_name", field: "var_name", toolTip: "var_name", width: 100},
		{id: "var_description", name: "var_description", field: "var_description", toolTip: "var_description", width: 300}
	];

	//displayColumns.unshift("id");
	var options = {
		enableCellNavigation: true,
        enableColumnReorder: false,
        explicitInitialization: true,
        editable: false,
		autosizeColsMode: true,
		fullWidthRows: true
	};
	
	function groupByPVUTypeDataset() {
		dataView.setGrouping([
			{
				getter: "var_pvu",
				formatter :function (g) {
					return g.value;
				},
				collapsed: false
			},
			{
				getter: "var_type",
				formatter :function (g) {
					return g.value;
				},
				collapsed: true
			},
			{
				getter: "var_dataset",
				formatter :function (g) {
					return g.value;
				},
				collapsed: true
			},
		]);
	}
	
	$(function () {
		var groupItemMetadataProvider = new Slick.Data.GroupItemMetadataProvider();
		dataView = new Slick.Data.DataView({
			groupItemMetadataProvider: groupItemMetadataProvider,
			inlineFilters: true
		});
		grid = new Slick.Grid("#grid_vars_second_step", dataView, columns, options);
        
		grid.registerPlugin(groupItemMetadataProvider);
		groupItemMetadataProvider.destroy();

		
		grid.setSelectionModel(new Slick.RowSelectionModel({selectActiveRow: false}));
		grid.registerPlugin(checkboxSelector);
		
		dataView.syncGridSelection(grid, true, true);

		dataView.onRowCountChanged.subscribe(function (e, args) {
		  grid.updateRowCount();
		  grid.render();
		});
		dataView.onRowsChanged.subscribe(function (e, args) {
			grid.invalidateRows(args.rows);
			grid.render();
		});
		grid.onSelectedRowsChanged.subscribe(function (evt, args) {
			grid.invalidateRows(args.rows);
			grid.render();
			
			variableChooser();
			datasetChooser();
		});

		dataView.beginUpdate();
		loadData();
		groupByPVUTypeDataset();
		grid.init();
		dataView.endUpdate()
		function variableChooser(){
			var selectedVars = [];
	
			selectedIndexes = grid.getSelectedRows();
			jQuery.each(selectedIndexes, function (index, value) {
				selectedVars.push(grid.getData().getItem(value)["var_name"]);
			});
			if(selectedVars.length > 0){
				document.getElementById("addColumns").disabled = false;
			}
			else{
				document.getElementById("addColumns").disabled = true;
			}	
			var xhr = new XMLHttpRequest();
			xhr.open("POST", "/variableChooserSecondStep", true);
			xhr.setRequestHeader("Content-Type", "application/json");
			xhr.send(JSON.stringify({ array: selectedVars }));
			console.log("post vc:");
			console.log(selectedVars);
		}
		function datasetChooser(){
			let selectedDatasets = new Set();
	
			selectedIndexes = grid.getSelectedRows();
			jQuery.each(selectedIndexes, function (index, value) {
				selectedDatasets.add(grid.getData().getItem(value)["var_dataset"]);
			});
			console.log(selectedDatasets);
			let arrDatasets = Array.from(selectedDatasets);

			var xhr = new XMLHttpRequest();
			xhr.open("POST", "/datasetChooserSecondStep", true);
			xhr.setRequestHeader("Content-Type", "application/json");
			xhr.send(JSON.stringify({ array: arrDatasets }));
			console.log("post dc:")
			console.log(arrDatasets)
		}
		
    });

}

function toggleDataGroups(){
	if(document.getElementById("countryYear").checked){
		$('#dyadicData').find('input[type=checkbox]:checked').prop('checked',false);				
		document.getElementById("countryYearData").style.display = "block";
		toggleVariableTableDiv();
	}
	else{
		$('#countryYearData').find('input[type=checkbox]:checked').prop('checked',false);
		document.getElementById("countryYearData").style.display = "none";
		toggleVariableTableDiv();
	}
	if(document.getElementById("dyadYear").checked){
		$('#countryYearData').find('input[type=checkbox]:checked').prop('checked',false);
		document.getElementById("dyadicData").style.display = "block";
		toggleVariableTableDiv();
	}
	else{
		$('#dyadicData').find('input[type=checkbox]:checked').prop('checked',false);				
		document.getElementById("dyadicData").style.display = "none";
		toggleVariableTableDiv();
	}
}

function toggleVariableTableDiv(){
	if(document.querySelectorAll('input[type="checkbox"]:checked').length >=1){
		document.getElementById("variableText").style.display = "block";
	}
	else{document.getElementById("variableText").style.display = "none";}	
	if(document.getElementById("NMC_5_0").checked){
		document.getElementById("divNMC_5_0_Table").style.display = "block";
	}
	else{					
		$('#divNMC_5_0_Table').find('input[type=checkbox]:checked').prop('checked',false);
		document.getElementById("divNMC_5_0_Table").style.display = "none";
	}
	if(document.getElementById("WRP_NAT").checked){
		document.getElementById("divWRP_NAT_Table").style.display = "block";
	}
	else{
		$('#divWRP_NAT_Table').find('input[type=checkbox]:checked').prop('checked',false);
		document.getElementById("divWRP_NAT_Table").style.display = "none";
	}
	if(document.getElementById("Major_Powers").checked){
		document.getElementById("divMajor_PowersTable").style.display = "block";
	}
	else{
		$('#divMajor_PowersTable').find('input[type=checkbox]:checked').prop('checked',false);		
		document.getElementById("divMajor_PowersTable").style.display = "none";
	}
	if(document.getElementById("DirectContiguity").checked){
		document.getElementById("divDirectContiguityTable").style.display = "block";
		if(document.querySelectorAll('input[type="checkbox"]:checked').length ==1){
			document.getElementById("variableText").style.display = "none";
		}
	}
	else{
		document.getElementById("divDirectContiguityTable").style.display = "none";
	}
	
	if(document.getElementById("MIDS_NDD").checked){
		document.getElementById("divMidDataTable").style.display = "block";
	}
	else{
		$('#divMidDataTable').find('input[type=checkbox]:checked').prop('checked',false);
		document.getElementById("divMidDataTable").style.display = "none";
	}
	if(document.getElementById("COW_Alliance_Data_NDD").checked){
		document.getElementById("divCOWAllianceDataTable").style.display = "block";
	}
	else{
		$('#divCOWAllianceDataTable').find('input[type=checkbox]:checked').prop('checked',false);
		document.getElementById("divCOWAllianceDataTable").style.display = "none";
	}
	if(document.getElementById("COW_IGO_Data_NDD").checked){
		document.getElementById("divCOWIGODataTable").style.display = "block";
	}
	else{
		$('#divCOWIGODataTable').find('input[type=checkbox]:checked').prop('checked',false);
		document.getElementById("divCOWIGODataTable").style.display = "none";
	}
	if(document.getElementById("COW_Diplomatic_Exchange").checked){
		document.getElementById("divCOWDiplomaticExchangeTable").style.display = "block";
	}
	else{
		$('#divCOWDiplomaticExchangeTable').find('input[type=checkbox]:checked').prop('checked',false);
		document.getElementById("divCOWDiplomaticExchangeTable").style.display = "none";
	}
	if(document.getElementById("COW_Trade_4_0").checked){
		document.getElementById("divCOWTradeTable").style.display = "block";
	}
	else{
		$('#divCOWTradeTable').find('input[type=checkbox]:checked').prop('checked',false);
		document.getElementById("divCOWTradeTable").style.display = "none";
	}
}

function variableChooserNSS(){
	const variables = [];
	if(document.getElementById("NMC_5_0").checked){
		variables.push("stateabb");
		variables.push("year");
		variables.push("ccode");
		if(document.getElementById("milex_NMC_5_0").checked){
			variables.push("milex");
		}
		if(document.getElementById("milper_NMC_5_0").checked){
			variables.push("milper");
		}
		if(document.getElementById("irst_NMC_5_0").checked){
			variables.push("irst");
		}
		if(document.getElementById("pec_NMC_5_0").checked){
			variables.push("pec");
		}
		if(document.getElementById("tpop_NMC_5_0").checked){
			variables.push("tpop");
		}
		if(document.getElementById("upop_NMC_5_0").checked){
			variables.push("upop");
		}
		if(document.getElementById("cinc_NMC_5_0").checked){
			variables.push("cinc");
		}
	}
	if(document.getElementById("Major_Powers").checked){
		variables.push("stateabb");
		variables.push("year");
		variables.push("ccode");
		variables.push("major");
	}
	if(document.getElementById("WRP_NAT").checked){
		variables.push("stateabb");
		variables.push("year");
		variables.push("ccode");
		if(document.getElementById("chrstprot_WRP_NAT").checked){
			variables.push("chrstprot");
		}
		if(document.getElementById("chrstcat_WRP_NAT").checked){
			variables.push("chrstcat");
		}
		if(document.getElementById("chrstorth_WRP_NAT").checked){
			variables.push("chrstorth");
		}
		if(document.getElementById("chrstang_WRP_NAT").checked){
			variables.push("chrstang");
		}
		if(document.getElementById("chrstothr_WRP_NAT").checked){
			variables.push("chrstothr");
		}
		if(document.getElementById("chrstgen_WRP_NAT").checked){
			variables.push("chrstgen");
		}
		if(document.getElementById("judorth_WRP_NAT").checked){
			variables.push("judorth");
		}
		if(document.getElementById("judcons_WRP_NAT").checked){
			variables.push("judcons");
		}
		if(document.getElementById("judref_WRP_NAT").checked){
			variables.push("judref");
		}
		if(document.getElementById("judothr_WRP_NAT").checked){
			variables.push("judothr");
		}
		if(document.getElementById("judgen_WRP_NAT").checked){
			variables.push("judgen");
		}
		if(document.getElementById("islmsun_WRP_NAT").checked){
			variables.push("islmsun");
		}
		if(document.getElementById("islmshi_WRP_NAT").checked){
			variables.push("islmshi");
		}
		if(document.getElementById("islmibd_WRP_NAT").checked){
			variables.push("islmibd");
		}
		if(document.getElementById("islmnat_WRP_NAT").checked){
			variables.push("islmnat");
		}
		if(document.getElementById("islmalw_WRP_NAT").checked){
			variables.push("islmalw");
		}
		if(document.getElementById("islmahm_WRP_NAT").checked){
			variables.push("islmahm");
		}
		if(document.getElementById("islmothr_WRP_NAT").checked){
			variables.push("islmothr");
		}
		if(document.getElementById("islmgen_WRP_NAT").checked){
			variables.push("islmgen");
		}
		if(document.getElementById("budmah_WRP_NAT").checked){
			variables.push("budmah");
		}
		if(document.getElementById("budthr_WRP_NAT").checked){
			variables.push("budthr");
		}
		if(document.getElementById("budothr_WRP_NAT").checked){
			variables.push("budothr");
		}
		if(document.getElementById("budgen_WRP_NAT").checked){
			variables.push("budgen");
		}
		if(document.getElementById("zorogen_WRP_NAT").checked){
			variables.push("zorogen");
		}
		if(document.getElementById("hindgen_WRP_NAT").checked){
			variables.push("hindgen");
		}
		if(document.getElementById("sikhgen_WRP_NAT").checked){
			variables.push("sikhgen");
		}
		if(document.getElementById("shntgen_WRP_NAT").checked){
			variables.push("shntgen");
		}
		if(document.getElementById("bahgen_WRP_NAT").checked){
			variables.push("bahgen");
		}
		if(document.getElementById("taogen_WRP_NAT").checked){
			variables.push("taogen");
		}
		if(document.getElementById("jaingen_WRP_NAT").checked){
			variables.push("jaingen");
		}
		if(document.getElementById("confgen_WRP_NAT").checked){
			variables.push("confgen");
		}
		if(document.getElementById("syncgen_WRP_NAT").checked){
			variables.push("syncgen");
		}
		if(document.getElementById("anmgen_WRP_NAT").checked){
			variables.push("anmgen");
		}
		if(document.getElementById("nonrelig_WRP_NAT").checked){
			variables.push("nonrelig");
		}
		if(document.getElementById("othrgen_WRP_NAT").checked){
			variables.push("othrgen");
		}
		if(document.getElementById("sumrelig_WRP_NAT").checked){
			variables.push("sumrelig");
		}
		if(document.getElementById("pop_WRP_NAT").checked){
			variables.push("pop");
		}
		if(document.getElementById("chrstprotpct_WRP_NAT").checked){
			variables.push("chrstprotpct");
		}
		if(document.getElementById("chrstcatpct_WRP_NAT").checked){
			variables.push("chrstcatpct");
		}
		if(document.getElementById("chrstorthpct_WRP_NAT").checked){
			variables.push("chrstorthpct");
		}
		if(document.getElementById("chrstangpct_WRP_NAT").checked){
			variables.push("chrstangpct");
		}
		if(document.getElementById("chrstothrpct_WRP_NAT").checked){
			variables.push("chrstothrpct");
		}
		if(document.getElementById("chrstgenpct_WRP_NAT").checked){
			variables.push("chrstgenpct");
		}
		if(document.getElementById("judorthpct_WRP_NAT").checked){
			variables.push("judorthpct");
		}
		if(document.getElementById("judconspct_WRP_NAT").checked){
			variables.push("judconspct");
		}
		if(document.getElementById("judrefpct_WRP_NAT").checked){
			variables.push("judrefpct");
		}
		if(document.getElementById("judothrpct_WRP_NAT").checked){
			variables.push("judothrpct");
		}
		if(document.getElementById("judgenpct_WRP_NAT").checked){
			variables.push("judgenpct");
		}
		if(document.getElementById("islmsunpct_WRP_NAT").checked){
			variables.push("islmsunpct");
		}
		if(document.getElementById("islmshipct_WRP_NAT").checked){
			variables.push("islmshipct");
		}
		if(document.getElementById("islmibdpct_WRP_NAT").checked){
			variables.push("islmibdpct");
		}
		if(document.getElementById("islmnatpct_WRP_NAT").checked){
			variables.push("islmnatpct");
		}
		if(document.getElementById("islmalwpct_WRP_NAT").checked){
			variables.push("islmalwpct");
		}
		if(document.getElementById("islmahmpct_WRP_NAT").checked){
			variables.push("islmahmpct");
		}
		if(document.getElementById("islmothrpct_WRP_NAT").checked){
			variables.push("islmothrpct");
		}
		if(document.getElementById("islmgenpct_WRP_NAT").checked){
			variables.push("islmgenpct");
		}
		if(document.getElementById("budmahpct_WRP_NAT").checked){
			variables.push("budmahpct");
		}
		if(document.getElementById("budthrpct_WRP_NAT").checked){
			variables.push("budthrpct");
		}
		if(document.getElementById("budothrpct_WRP_NAT").checked){
			variables.push("budothrpct");
		}
		if(document.getElementById("budgenpct_WRP_NAT").checked){
			variables.push("budgenpct");
		}
		if(document.getElementById("zorogenpct_WRP_NAT").checked){
			variables.push("zorogenpct");
		}
		if(document.getElementById("hindgenpct_WRP_NAT").checked){
			variables.push("hindgenpct");
		}
		if(document.getElementById("sikhgenpct_WRP_NAT").checked){
			variables.push("sikhgenpct");
		}
		if(document.getElementById("shntgenpct_WRP_NAT").checked){
			variables.push("shntgenpct");
		}
		if(document.getElementById("bahgenpct_WRP_NAT").checked){
			variables.push("bahgenpct");
		}
		if(document.getElementById("taogenpct_WRP_NAT").checked){
			variables.push("taogenpct");
		}
		if(document.getElementById("jaingenpct_WRP_NAT").checked){
			variables.push("jaingenpct");
		}
		if(document.getElementById("confgenpct_WRP_NAT").checked){
			variables.push("confgenpct");
		}
		if(document.getElementById("syncgenpct_WRP_NAT").checked){
			variables.push("syncgenpct");
		}
		if(document.getElementById("anmgenpct_WRP_NAT").checked){
			variables.push("anmgenpct");
		}
		if(document.getElementById("nonreligpct_WRP_NAT").checked){
			variables.push("nonreligpct");
		}
		if(document.getElementById("othrgenpct_WRP_NAT").checked){
			variables.push("othrgenpct");
		}
		if(document.getElementById("sumreligpct_WRP_NAT").checked){
			variables.push("sumreligpct");
		}
		if(document.getElementById("total_WRP_NAT").checked){
			variables.push("total");
		}
		if(document.getElementById("dualrelig_WRP_NAT").checked){
			variables.push("dualrelig");
		}
		if(document.getElementById("datatype_WRP_NAT").checked){
			variables.push("datatype");
		}
		if(document.getElementById("recreliab_WRP_NAT").checked){
			variables.push("recreliab");
		}
		if(document.getElementById("reliabilevel_WRP_NAT").checked){
			variables.push("reliabilevel");
		}
		if(document.getElementById("sourcecode_WRP_NAT").checked){
			variables.push("sourcecode");
		}
	}
	if(document.getElementById("DirectContiguity").checked){
		variables.push("ccode1");
		variables.push("stateabb1");
		variables.push("ccode2");
		variables.push("stateabb2");
		variables.push("year");
		variables.push("conttype");
	}
	if(document.getElementById("MIDS_NDD").checked){
		variables.push("ccode1");
		variables.push("stateabb1");
		variables.push("ccode2");
		variables.push("stateabb2");
		variables.push("year");
		if(document.getElementById("mid_count_MID").checked){
			variables.push("mid_count");
		}
		if(document.getElementById("mid_onset_m_MID").checked){
			variables.push("mid_onset_m");
		}
		if(document.getElementById("mid_ongoing_m_MID").checked){
			variables.push("mid_ongoing_m");
		}
		/*if(document.getElementById("onset_other_MID").checked){
			variables.push("onset_other");
		}
		if(document.getElementById("ongoing_other_MID").checked){
			variables.push("ongoing_other");
		}
		if(document.getElementById("main_disno_MID").checked){
			variables.push("main_disno");
		}
		if(document.getElementById("dyindex_MID").checked){
			variables.push("dyindex");
		}
		if(document.getElementById("strtday_m_MID").checked){
			variables.push("strtday_m");
		}
		if(document.getElementById("strtmnth_m_MID").checked){
			variables.push("strtmnth_m");
		}
		if(document.getElementById("strtyr_m_MID").checked){
			variables.push("strtyr_m");
		}
		if(document.getElementById("endday_m_MID").checked){
			variables.push("endday_m");
		}
		if(document.getElementById("endmnth_m_MID").checked){
			variables.push("endmnth_m");
		}
		if(document.getElementById("endyear_m_MID").checked){
			variables.push("endyear_m");
		}*/
		if(document.getElementById("outcome_m_MID").checked){
			variables.push("outcome_m");
		}/*
		if(document.getElementById("settlmnt_m_MID").checked){
			variables.push("settlmnt_m");
		}*/
		if(document.getElementById("fatlev_m_MID").checked){
			variables.push("fatlev_m");
		}/*
		if(document.getElementById("highact_m_MID").checked){
			variables.push("highact_m");
		}*/
		if(document.getElementById("hihost_m_MID").checked){
			variables.push("hihost_m");
		}/*
		if(document.getElementById("recip_m_MID").checked){
			variables.push("recip_m");
		}
		if(document.getElementById("nosideA_m_MID").checked){
			variables.push("nosideA_m");
		}
		if(document.getElementById("nosideB_m_MID").checked){
			variables.push("nosideB_m");
		}
		if(document.getElementById("sideaa_m_MID").checked){
			variables.push("sideaa_m");
		}
		if(document.getElementById("revstata_m_MID").checked){
			variables.push("revstata_m");
		}
		if(document.getElementById("revtypea_m_MID").checked){
			variables.push("revtypea_m");
		}
		if(document.getElementById("fatleva_m_MID").checked){
			variables.push("fatleva_m");
		}
		if(document.getElementById("highmcaa_m_MID").checked){
			variables.push("highmcaa_m");
		}
		if(document.getElementById("hihosta_m_MID").checked){
			variables.push("hihosta_m");
		}
		if(document.getElementById("orignata_m_MID").checked){
			variables.push("orignata_m");
		}
		if(document.getElementById("sideab_m_MID").checked){
			variables.push("sideab_m");
		}
		if(document.getElementById("revstatb_m_MID").checked){
			variables.push("revstatb_m");
		}
		if(document.getElementById("revtypeb_m_MID").checked){
			variables.push("revtypeb_m");
		}
		if(document.getElementById("fatlevb_m_MID").checked){
			variables.push("fatlevb_m");
		}
		if(document.getElementById("highmcab_m_MID").checked){
			variables.push("highmcab_m");
		}
		if(document.getElementById("hihostb_m_MID").checked){
			variables.push("hihostb_m");
		}
		if(document.getElementById("orignatb_m_MID").checked){
			variables.push("orignatb_m");
		}
		if(document.getElementById("rolea_m_MID").checked){
			variables.push("rolea_m");
		}
		if(document.getElementById("roleb_m_MID").checked){
			variables.push("roleb_m");
		}
		if(document.getElementById("dyad_rolea_m_MID").checked){
			variables.push("dyad_rolea_m");
		}
		if(document.getElementById("dyad_roleb_m_MID").checked){
			variables.push("dyad_roleb_m");
		}*/
		if(document.getElementById("war_m_MID").checked){
			variables.push("war_m");
		}/*
		if(document.getElementById("durindx_m_MID").checked){
			variables.push("durindx_m");
		}
		if(document.getElementById("duration_m_MID").checked){
			variables.push("duration_m");
		}
		if(document.getElementById("cumdurat_m_MID").checked){
			variables.push("cumdurat_m");
		}
		if(document.getElementById("mid5hiact_m_MID").checked){
			variables.push("mid5hiact_m");
		}
		if(document.getElementById("mid5hiacta_m_MID").checked){
			variables.push("mid5hiacta_m");
		}
		if(document.getElementById("mid5hiactb_m_MID").checked){
			variables.push("mid5hiactb_m");
		}
		if(document.getElementById("severity_m_MID").checked){
			variables.push("severity_m");
		}
		if(document.getElementById("severitya_m_MID").checked){
			variables.push("severitya_m");
		}
		if(document.getElementById("severityb_m_MID").checked){
			variables.push("severityb_m");
		}
		if(document.getElementById("ongo2014_m_MID").checked){
			variables.push("ongo2014_m");
		}
		if(document.getElementById("new_m_MID").checked){
			variables.push("new_m");
		}*/
	}
	if(document.getElementById("COW_Alliance_Data_NDD").checked){
		variables.push("ccode1");
		variables.push("stateabb1");
		variables.push("ccode2");
		variables.push("stateabb2");
		variables.push("year");
		if(document.getElementById("defense_Alliance").checked){
			variables.push("defense");
		}
		if(document.getElementById("neutrality_Alliance").checked){
			variables.push("neutrality");
		}
		if(document.getElementById("nonaggression_Alliance").checked){
			variables.push("nonaggression");
		}
		if(document.getElementById("entente_Alliance").checked){
			variables.push("entente");
		}
	}
	if(document.getElementById("COW_IGO_Data_NDD").checked){
		variables.push("ccode1");
		variables.push("stateabb1");
		variables.push("ccode2");
		variables.push("stateabb2");
		variables.push("year");
		if(document.getElementById("joint_igo_membership_IGO").checked){
			variables.push("joint_igo_membership");
		}
		if(document.getElementById("joint_igo_membership_count_IGO").checked){
			variables.push("joint_igo_membership_count");
		}
	}
	if(document.getElementById("COW_Diplomatic_Exchange").checked){
		variables.push("ccode1");
		variables.push("stateabb1");
		variables.push("ccode2");
		variables.push("stateabb2");
		variables.push("year");
		if(document.getElementById("dr_at_1_Diplo").checked){
			variables.push("dr_at_1");
		}
		if(document.getElementById("dr_at_2_Diplo").checked){
			variables.push("dr_at_2");
		}
		if(document.getElementById("de_Diplo").checked){
			variables.push("de");
		}
	}
	if(document.getElementById("COW_Trade_4_0").checked){
		variables.push("ccode1");
		variables.push("stateabb1");
		variables.push("ccode2");
		variables.push("stateabb2");
		variables.push("year");
		if(document.getElementById("flow1_Trade").checked){
			variables.push("flow1");
		}
		if(document.getElementById("flow2_Trade").checked){
			variables.push("flow2");
		}
		if(document.getElementById("smoothflow1_Trade").checked){
			variables.push("smoothflow1");
		}
		if(document.getElementById("smoothflow2_Trade").checked){
			variables.push("smoothflow2");
		}
		if(document.getElementById("smoothtotrade_Trade").checked){
			variables.push("smoothtotrade");
		}
		if(document.getElementById("china_alt_flow1_Trade").checked){
			variables.push("china_alt_flow1");
		}
	}
	var xhr = new XMLHttpRequest();
	xhr.open("POST", "/variableChooser", true);
	xhr.setRequestHeader("Content-Type", "application/json");
	xhr.send(JSON.stringify({ array: variables }));
	console.log("post vc:");
	console.log(variables);
	return variables;
}


function containsAll(obj, arr){
   for(var i = 0; i < arr.length; i++){
      if(Object.keys(obj).includes(arr[i])){
         continue;
      }else{
         return false;
      }
   }
   return true;
}

function checkCheckboxes(){
	let tf = true;
	if (document.querySelectorAll('input[type="checkbox"]:checked').length <1){
		tf = false;
	}
	if(((variableChooser().length <=3) & ((document.getElementById("countryYear").checked))| (variableChooser().length <=5) & (document.getElementById("dyadYear").checked))){
		tf = false;
	}
	return Boolean(tf);
}

function hideBusyMessage() {
	const busyMessage = document.getElementById('busyMessage');
	busyMessage.style.display = 'none';
}
  
function showBusyMessage() {
	const busyMessage = document.getElementById('busyMessage');
	busyMessage.style.display = 'block';
}

function hideLoadingMessage() {
	const loadingMessage = document.getElementById('loadingMessage');
	loadingMessage.style.display = 'none';
}
  
function showLoadingMessage() {
	const loadingMessage = document.getElementById('loadingMessage');
	loadingMessage.style.display = 'block';
}

function hideDownloadMessage() {
	const downloadMessage = document.getElementById('downloadMessage');
	downloadMessage.style.display = 'none';
}
  
function showDownloadMessage() {
	const downloadMessage = document.getElementById('downloadMessage');
	downloadMessage.style.display = 'block';
}

async function retrieveJSON() {
    var myData = [];

    try {
		showLoadingMessage();
        const response = await fetch('createDf'); // issues a GET request by default
        const data = await response.json(); // data becomes the response from create_df(), which is { 'message': 'data processing successful', 'status': 200, 'new_df': new_df }
        // access the new_df data from the response
		const newdf = data.new_df; // this js constant is set to the new_df output from the response, which is a JSON array
        // populate myData with new_df
		myData = JSON.parse(newdf);
    } catch (error) {
		console.error('error processing data:', error);
    } finally {
		hideLoadingMessage();
	}
    return myData;
}
	
async function retrieveJSONSecondStep() {
    var myData = [];

    try {
        const response = await fetch('createDfSS'); // issues a GET request by default
        const data = await response.json(); // data becomes the response from create_df(), which is { 'message': 'data processing successful', 'status': 200, 'new_df': new_df }
        // access the new_df data from the response
		const new_df = data.new_df; // this js constant is set to the new_df output from the response, which is a JSON array
        // populate myData with new_df
        myData = JSON.parse(new_df);
    } catch (error) {
		console.error('error processing data:', error);
    }
    return myData;
}

function BackButtonOne(){
	document.getElementById("qChooseCY").style.display = "none";
	document.getElementById("backButton1").style.display = "none";
	document.getElementById("createButtonSecondStep").style.display = "none";
	document.getElementById("createButton").style.display = "inline-block";
	document.getElementById("optionsPanel").style.display = "none";
	document.getElementById("FirstStep").style.display = "block";
	document.getElementById("grid_vars_first_step").style.display = "block";
	document.getElementById("SecondStep").style.display = "none";
	document.getElementById("SecondStepVars").style.display = "none";
	document.getElementById("backButton2").style.display = "none";
	document.getElementById("downloadButton").style.display = "none";
	document.getElementById("downloadButton2").style.display = "none";
	$('#SecondStep').find('input[type=checkbox]:checked').prop('checked',false);
	$('#SecondStep').find('input[type=radio]:checked').prop('checked',false);
	document.getElementById("myTable").style.display = "none";
	document.getElementById("yesChooseCY").disabled = false;
	document.getElementById("noChooseCY").disabled = false;
	filterYearMin = 1000;
	filterYearMax = 3000;
	filterState1 = [];
	filterState2 = [];
}

async function retrieveBackButtonTwo() {
    var myData = [];

    try {
        const response = await fetch('backbutton2'); // issues a GET request by default
        const data = await response.json(); // data becomes the response from create_df(), which is { 'message': 'data processing successful', 'status': 200, 'new_df': new_df }
        // access the new_df data from the response
		const new_df = data.new_df; // this js constant is set to the new_df output from the response, which is a JSON array
        // populate myData with new_df
        myData = JSON.parse(new_df);
    } catch (error) {
		console.error('error processing data:', error);
    }
    return myData;
}

function BackButtonTwo(){
	hideDownloadMessage()
	if(dyadmonad == "dyadic"){
		document.getElementById("qChooseCY").style.display = "block";
		document.getElementById("backButton1").style.display = "inline-block";
		document.getElementById("createButtonSecondStep").style.display = "inline-block";
		document.getElementById("createButton").style.display = "none";
		document.getElementById("FirstStep").style.display = "none";
		document.getElementById("grid_vars_first_step").style.display = "none";
		document.getElementById("SecondStep").style.display = "block";
		document.getElementById("SecondStepVars").style.display = "none";
		document.getElementById("grid_vars_second_step").style.display = "none";
		document.getElementById("backButton2").style.display = "none";
		document.getElementById("downloadButton").style.display = "none";
		document.getElementById("downloadButton2").style.display = "none";
		// document.getElementById("variableTablesSecondStep").style.display = "none";
		$('#SecondStep').find('input[type=checkbox]:checked').prop('checked',false);
		$('#SecondStep').find('input[type=radio]:checked').prop('checked',false);
		document.getElementById("yesChooseCY").disabled = false;
		document.getElementById("noChooseCY").disabled = false;
		document.getElementById("myTable").style.display = "inline-block";
		document.getElementById("addColumns").disabled = true;
		BackButton2_CreateTable();
		filterYearMin = 1000;
		filterYearMax = 3000;
		filterState1 = [];
		filterState2 = [];
	}
	else if(dyadmonad == "monadic"){
		document.getElementById("createButton").style.display = "inline-block";
		document.getElementById("createButton").disabled = false;
		document.getElementById("backButton1").style.display = "none";
		document.getElementById("backButton2").style.display = "none";
		document.getElementById("downloadButton").style.display = "none";
		document.getElementById("downloadButton2").style.display = "none";
		document.getElementById("FirstStep").style.display = "block";
		document.getElementById("grid_vars_first_step").style.display = "block";
		document.getElementById("SecondStep").style.display = "none";
		document.getElementById("optionsPanel").style.display = "none";
		$('#SecondStep').find('input[type=checkbox]:checked').prop('checked',false);
		$('#SecondStep').find('input[type=radio]:checked').prop('checked',false);
		document.getElementById("myTable").style.display = "none";
		filterYearMin = 1000;
		filterYearMax = 3000;
		filterState1 = [];
		filterState2 = [];
	}
}

var filteredItems = [];
async function CreateTable(){
	document.getElementById("createButton").disabled = true;
	console.log("CreateTable() called")
	var yearRangeMin = "0";
	var yearRangeMax = "2022";
	var dataView;
	var grid;
	// let truefalse = checkCheckboxes();
	// if(truefalse == false){
	// 	document.getElementById("Warning").style.display = "block";
	// 	return;
	// }
	// else{
	// 	document.getElementById("Warning").style.display = "none";				
	// }
	var myData = await retrieveJSON(); 
	//displayColumns.unshift("id");
	var col = [];
	keys = Object.keys(myData[0]);
	for (var key in keys) {
		col.push({id: keys[key], name: keys[key], field: keys[key], toolTip: keys[key]});
	}
	var options = {
		enableCellNavigation: true,
        enableColumnReorder: false,
        explicitInitialization: true,
        editable: false,
	};
		
	$(function () {
		dataView = new Slick.Data.DataView();
		grid = new Slick.Grid("#myGrid", dataView, col, options);
		
        grid.setSelectionModel(new Slick.CellSelectionModel());

		dataView.onRowCountChanged.subscribe(function (e, args) {
		  grid.updateRowCount();
		  grid.render();
		});
		dataView.onRowsChanged.subscribe(function (e, args) {
		  grid.invalidateRows(args.rows);
		  grid.render();
		});
		
		$("#yearRangeMinimum").keyup(function (e) {
			Slick.GlobalEditorLock.cancelCurrentEdit();

			if (e.which == 27) {
			  this.value = "0";
			}

			yearRangeMin = this.value;
			filterYearMin = yearRangeMin;
			updateFilter();
		});
		$("#yearRangeMaximum").keyup(function (e) {
			Slick.GlobalEditorLock.cancelCurrentEdit();

			if (e.which == 27) {
			  this.value = "2022";
			}
			yearRangeMax = this.value;
			filterYearMax = yearRangeMax;
			updateFilter();
		});
		
		function updateFilter() {
			dataView.setFilterArgs({
			  yearRangeMin: yearRangeMin,
			  yearRangeMax: yearRangeMax
			});
			dataView.refresh();
		}
		grid.init();
		dataView.beginUpdate();
		dataView.setItems(myData);
		dataView.setFilterArgs({
			yearRangeMin: yearRangeMin,
			yearRangeMax: yearRangeMax
		});
		dataView.setFilter(filter);
		
		dataView.endUpdate();
		
		var filterPlugin = new Ext.Plugins.HeaderFilter({});

            filterPlugin.onFilterApplied.subscribe(function () {
                dataView.refresh();
                grid.resetActiveCell();
				filteredItems = dataView.getRows();
            });


            grid.registerPlugin(filterPlugin);

            

            grid.init();
            function filter(item, args) {
                var columns = grid.getColumns();
				var filterValues = [];
                var value = true;
				
                for (var i = 0; i < columns.length; i++) {
                    var col = columns[i];
                    filterValues = col.filterValues;

                    if (filterValues && filterValues.length > 0) {
                        value = value & _.contains(filterValues, item[col.field]);
                    }
                }
				
				if (args.yearRangeMin != "" && item["year"] < parseInt(args.yearRangeMin)) {
					value = false;
				}
				if (args.yearRangeMax != "" && item["year"] > parseInt(args.yearRangeMax)){
					value = false;
				}
				if(columns[1].filterValues != undefined){
					filterState1 = columns[1].filterValues;
				}
				if(dyadmonad == "dyadic"){
					if(columns[3].filterValues != undefined){
						filterState2 = columns[3].filterValues;
					}
				}
                return value;
            }
			
		filteredItems = dataView.getRows();
    });
	
	if (dyadmonad == "dyadic"){
		document.getElementById("qChooseCY").style.display = "block";
		changeButton();
	}
	else if(dyadmonad == "monadic"){
		changeButtonSecondStep();
	}
	document.getElementById("grid_vars_first_step").style.display = "none";
	document.getElementById("FirstStep").style.display = "none";
	document.getElementById("myTable").style.display = "inline-block";
	document.getElementById("optionsPanel").style.display = "inline-block";
	document.getElementById("SecondStep").style.display = "block";
	document.getElementById("addColumns").disabled = true;
}


async function BackButton2_CreateTable(){
	console.log("BackButton2() called")
	var yearRangeMin = "0";
	var yearRangeMax = "2022";
	var dataView;
	var grid;
	// let truefalse = checkCheckboxes();
	// if(truefalse == false){
	// 	document.getElementById("Warning").style.display = "block";
	// 	return;
	// }
	// else{
	// 	document.getElementById("Warning").style.display = "none";				
	// }

	var myData = await retrieveBackButtonTwo(); 
	//displayColumns.unshift("id");
	var col = [];
	keys = Object.keys(myData[0])
	for (var key in keys) {
		col.push({id: keys[key], name: keys[key], field: keys[key], toolTip: keys[key]});
	}
	var options = {
		enableCellNavigation: true,
        enableColumnReorder: false,
        explicitInitialization: true,
        editable: false,
	};
		
	$(function () {
		dataView = new Slick.Data.DataView();
		grid = new Slick.Grid("#myGrid", dataView, col, options);
		
        grid.setSelectionModel(new Slick.CellSelectionModel());

		dataView.onRowCountChanged.subscribe(function (e, args) {
		  grid.updateRowCount();
		  grid.render();
		});
		dataView.onRowsChanged.subscribe(function (e, args) {
		  grid.invalidateRows(args.rows);
		  grid.render();
		});
		
		$("#yearRangeMinimum").keyup(function (e) {
			Slick.GlobalEditorLock.cancelCurrentEdit();

			if (e.which == 27) {
			  this.value = "0";
			}

			yearRangeMin = this.value;
			filterYearMin = yearRangeMin;
			updateFilter();
		});
		$("#yearRangeMaximum").keyup(function (e) {
			Slick.GlobalEditorLock.cancelCurrentEdit();

			if (e.which == 27) {
			  this.value = "2022";
			}
			yearRangeMax = this.value;
			filterYearMax = yearRangeMax;
			updateFilter();
		});
		
		function updateFilter() {
			dataView.setFilterArgs({
			  yearRangeMin: yearRangeMin,
			  yearRangeMax: yearRangeMax
			});
			dataView.refresh();
		}
		grid.init();
		dataView.beginUpdate();
		dataView.setItems(myData);
		dataView.setFilterArgs({
			yearRangeMin: yearRangeMin,
			yearRangeMax: yearRangeMax
		});
		dataView.setFilter(filter);
		
		dataView.endUpdate();
		
		var filterPlugin = new Ext.Plugins.HeaderFilter({});

            filterPlugin.onFilterApplied.subscribe(function () {
                dataView.refresh();
                grid.resetActiveCell();
				filteredItems = dataView.getRows();
            });


            grid.registerPlugin(filterPlugin);

            

            grid.init();
            function filter(item, args) {
                var columns = grid.getColumns();
				var filterValues = [];
                var value = true;
				
                for (var i = 0; i < columns.length; i++) {
                    var col = columns[i];
                    filterValues = col.filterValues;

                    if (filterValues && filterValues.length > 0) {
                        value = value & _.contains(filterValues, item[col.field]);
                    }
                }
				
				if (args.yearRangeMin != "" && item["year"] < parseInt(args.yearRangeMin)) {
					value = false;
				}
				if (args.yearRangeMax != "" && item["year"] > parseInt(args.yearRangeMax)){
					value = false;
				}
				if(columns[1].filterValues != undefined){
					filterState1 = columns[1].filterValues;
				}
				if(dyadmonad == "dyadic"){
					if(columns[3].filterValues != undefined){
						filterState2 = columns[3].filterValues;
					}
				}
                return value;
            }
		filteredItems = dataView.getRows();
    });
	
	document.getElementById("myTable").style.display = "inline-block";
	document.getElementById("optionsPanel").style.display = "inline-block";
	document.getElementById("FirstStep").style.display = "none";
	document.getElementById("SecondStep").style.display = "block";
}

//SECOND STEP 
function displayChooseCYData(){
	// document.getElementById("yesChooseCY").disabled = true;
	// document.getElementById("noChooseCY").disabled = true;
	if(document.getElementById("yesChooseCY").checked){
		VarTable_S2();
		document.getElementById("SecondStepVars").style.display = "block";
		document.getElementById("table_vars_second_step").style.display = "inline-block";
		document.getElementById("grid_vars_second_step").style.display = "inline-block";
	}
	if (document.getElementById("noChooseCY").checked){
		document.getElementById("addColumns").disabled = false;
		changeButtonSecondStep();
		//toggleSelectors();
	}
}

function checkCheckboxesSecondStep(){
	let tf = true;
	if (document.querySelectorAll('input[type="checkbox"]:checked').length <1){
		tf = false;
	}
	if($('input[name*="NMC_5_0SecondStep"]:checked').length < 1 && $('input[name*="WRP_NATSecondStep"]:checked').length < 1 && $('input[name*="Major_PowersSecondStep"]:checked').length < 1){
		tf = false;
	}
	if($('input[name*="SecondStep"]:checked').length < 1){
		tf = false;
	}
	return Boolean(tf);
}

function changeButton(){
	document.getElementById("backButton1").style.display = "inline-block";
	document.getElementById("createButtonSecondStep").style.display = "inline-block";
	document.getElementById("createButton").style.display = "none";
}

function changeButtonSecondStep(){
	document.getElementById("createButtonSecondStep").style.display = "none";
	document.getElementById("createButton").style.display = "none";
	document.getElementById("backButton1").style.display = "none";
	document.getElementById("backButton2").style.display = "inline-block";
	document.getElementById("downloadButton").style.display = "inline-block";
	document.getElementById("downloadButton2").style.display = "inline-block";
	document.getElementById("SecondStep").style.display = "none";
	document.getElementById("grid_vars_first_step").style.display = "none";
	document.getElementById("grid_vars_second_step").style.display = "none";
} 

function toggleVariableTableDivSecondStep(){
	document.getElementById("variableTablesSecondStep").style.display = "block";

	if(document.querySelectorAll('input[type="checkbox"]:checked').length >=1){
		document.getElementById("variableText").style.display = "block";
	}
	else{document.getElementById("variableText").style.display = "none";}
	if(document.getElementById("NMC_5_0SecondStep").checked){
		document.getElementById("divNMC_5_0_TableSecondStep").style.display = "block";
	}
	else{					
		$('#divNMC_5_0_TableSecondStep').find('input[type=checkbox]:checked').prop('checked',false);
		document.getElementById("divNMC_5_0_TableSecondStep").style.display = "none";
	}
	if(document.getElementById("WRP_NATSecondStep").checked){
		document.getElementById("divWRP_NAT_TableSecondStep").style.display = "block";
	}
	else{
		$('#divWRP_NAT_TableSecondStep').find('input[type=checkbox]:checked').prop('checked',false);
		document.getElementById("divWRP_NAT_TableSecondStep").style.display = "none";
	}
	if(document.getElementById("Major_PowersSecondStep").checked){
		document.getElementById("divMajor_PowersTableSecondStep").style.display = "block";
	}
	else{
		document.getElementById("divMajor_PowersTableSecondStep").style.display = "none";
	}
}

function variableChooserSecondStepNSS(){
	const variablesSecondStep = [];
	if(document.getElementById("NMC_5_0SecondStep").checked){
		if(document.getElementById("milex_NMC_5_0SecondStep").checked){
			variablesSecondStep.push("milex");
		}
		if(document.getElementById("milper_NMC_5_0SecondStep").checked){
			variablesSecondStep.push("milper");
		}
		if(document.getElementById("irst_NMC_5_0SecondStep").checked){
			variablesSecondStep.push("irst");
		}
		if(document.getElementById("pec_NMC_5_0SecondStep").checked){
			variablesSecondStep.push("pec");
		}
		if(document.getElementById("tpop_NMC_5_0SecondStep").checked){
			variablesSecondStep.push("tpop");
		}
		if(document.getElementById("upop_NMC_5_0SecondStep").checked){
			variablesSecondStep.push("upop");
		}
		if(document.getElementById("cinc_NMC_5_0SecondStep").checked){
			variablesSecondStep.push("cinc");
		}
	}
	if(document.getElementById("Major_PowersSecondStep").checked){
		variablesSecondStep.push("major");
	}
	if(document.getElementById("WRP_NATSecondStep").checked){
		if(document.getElementById("chrstprot_WRP_NATSecondStep").checked){
			variablesSecondStep.push("chrstprot");
		}
		if(document.getElementById("chrstcat_WRP_NATSecondStep").checked){
			variablesSecondStep.push("chrstcat");
		}
		if(document.getElementById("chrstorth_WRP_NATSecondStep").checked){
			variablesSecondStep.push("chrstorth");
		}
		if(document.getElementById("chrstang_WRP_NATSecondStep").checked){
			variablesSecondStep.push("chrstang");
		}
		if(document.getElementById("chrstothr_WRP_NATSecondStep").checked){
			variablesSecondStep.push("chrstothr");
		}
		if(document.getElementById("chrstgen_WRP_NATSecondStep").checked){
			variablesSecondStep.push("chrstgen");
		}
		if(document.getElementById("judorth_WRP_NATSecondStep").checked){
			variablesSecondStep.push("judorth");
		}
		if(document.getElementById("judcons_WRP_NATSecondStep").checked){
			variablesSecondStep.push("judcons");
		}
		if(document.getElementById("judref_WRP_NATSecondStep").checked){
			variablesSecondStep.push("judref");
		}
		if(document.getElementById("judothr_WRP_NATSecondStep").checked){
			variablesSecondStep.push("judothr");
		}
		if(document.getElementById("judgen_WRP_NATSecondStep").checked){
			variablesSecondStep.push("judgen");
		}
		if(document.getElementById("islmsun_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmsun");
		}
		if(document.getElementById("islmshi_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmshi");
		}
		if(document.getElementById("islmibd_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmibd");
		}
		if(document.getElementById("islmnat_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmnat");
		}
		if(document.getElementById("islmalw_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmalw");
		}
		if(document.getElementById("islmahm_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmahm");
		}
		if(document.getElementById("islmothr_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmothr");
		}
		if(document.getElementById("islmgen_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmgen");
		}
		if(document.getElementById("budmah_WRP_NATSecondStep").checked){
			variablesSecondStep.push("budmah");
		}
		if(document.getElementById("budthr_WRP_NATSecondStep").checked){
			variablesSecondStep.push("budthr");
		}
		if(document.getElementById("budothr_WRP_NATSecondStep").checked){
			variablesSecondStep.push("budothr");
		}
		if(document.getElementById("budgen_WRP_NATSecondStep").checked){
			variablesSecondStep.push("budgen");
		}
		if(document.getElementById("zorogen_WRP_NATSecondStep").checked){
			variablesSecondStep.push("zorogen");
		}
		if(document.getElementById("hindgen_WRP_NATSecondStep").checked){
			variablesSecondStep.push("hindgen");
		}
		if(document.getElementById("sikhgen_WRP_NATSecondStep").checked){
			variablesSecondStep.push("sikhgen");
		}
		if(document.getElementById("shntgen_WRP_NATSecondStep").checked){
			variablesSecondStep.push("shntgen");
		}
		if(document.getElementById("bahgen_WRP_NATSecondStep").checked){
			variablesSecondStep.push("bahgen");
		}
		if(document.getElementById("taogen_WRP_NATSecondStep").checked){
			variablesSecondStep.push("taogen");
		}
		if(document.getElementById("jaingen_WRP_NATSecondStep").checked){
			variablesSecondStep.push("jaingen");
		}
		if(document.getElementById("confgen_WRP_NATSecondStep").checked){
			variablesSecondStep.push("confgen");
		}
		if(document.getElementById("syncgen_WRP_NATSecondStep").checked){
			variablesSecondStep.push("syncgen");
		}
		if(document.getElementById("anmgen_WRP_NATSecondStep").checked){
			variablesSecondStep.push("anmgen");
		}
		if(document.getElementById("nonrelig_WRP_NATSecondStep").checked){
			variablesSecondStep.push("nonrelig");
		}
		if(document.getElementById("othrgen_WRP_NATSecondStep").checked){
			variablesSecondStep.push("othrgen");
		}
		if(document.getElementById("sumrelig_WRP_NATSecondStep").checked){
			variablesSecondStep.push("sumrelig");
		}
		if(document.getElementById("pop_WRP_NATSecondStep").checked){
			variablesSecondStep.push("pop");
		}
		if(document.getElementById("chrstprotpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("chrstprotpct");
		}
		if(document.getElementById("chrstcatpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("chrstcatpct");
		}
		if(document.getElementById("chrstorthpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("chrstorthpct");
		}
		if(document.getElementById("chrstangpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("chrstangpct");
		}
		if(document.getElementById("chrstothrpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("chrstothrpct");
		}
		if(document.getElementById("chrstgenpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("chrstgenpct");
		}
		if(document.getElementById("judorthpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("judorthpct");
		}
		if(document.getElementById("judconspct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("judconspct");
		}
		if(document.getElementById("judrefpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("judrefpct");
		}
		if(document.getElementById("judothrpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("judothrpct");
		}
		if(document.getElementById("judgenpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("judgenpct");
		}
		if(document.getElementById("islmsunpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmsunpct");
		}
		if(document.getElementById("islmshipct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmshipct");
		}
		if(document.getElementById("islmibdpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmibdpct");
		}
		if(document.getElementById("islmnatpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmnatpct");
		}
		if(document.getElementById("islmalwpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmalwpct");
		}
		if(document.getElementById("islmahmpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmahmpct");
		}
		if(document.getElementById("islmothrpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmothrpct");
		}
		if(document.getElementById("islmgenpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("islmgenpct");
		}
		if(document.getElementById("budmahpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("budmahpct");
		}
		if(document.getElementById("budthrpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("budthrpct");
		}
		if(document.getElementById("budothrpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("budothrpct");
		}
		if(document.getElementById("budgenpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("budgenpct");
		}
		if(document.getElementById("zorogenpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("zorogenpct");
		}
		if(document.getElementById("hindgenpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("hindgenpct");
		}
		if(document.getElementById("sikhgenpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("sikhgenpct");
		}
		if(document.getElementById("shntgenpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("shntgenpct");
		}
		if(document.getElementById("bahgenpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("bahgenpct");
		}
		if(document.getElementById("taogenpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("taogenpct");
		}
		if(document.getElementById("jaingenpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("jaingenpct");
		}
		if(document.getElementById("confgenpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("confgenpct");
		}
		if(document.getElementById("syncgenpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("syncgenpct");
		}
		if(document.getElementById("anmgenpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("anmgenpct");
		}
		if(document.getElementById("nonreligpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("nonreligpct");
		}
		if(document.getElementById("othrgenpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("othrgenpct");
		}
		if(document.getElementById("sumreligpct_WRP_NATSecondStep").checked){
			variablesSecondStep.push("sumreligpct");
		}
		if(document.getElementById("total_WRP_NATSecondStep").checked){
			variablesSecondStep.push("total");
		}
		if(document.getElementById("dualrelig_WRP_NATSecondStep").checked){
			variablesSecondStep.push("dualrelig");
		}
		if(document.getElementById("datatype_WRP_NATSecondStep").checked){
			variablesSecondStep.push("datatype");
		}
		if(document.getElementById("recreliab_WRP_NATSecondStep").checked){
			variablesSecondStep.push("recreliab");
		}
		if(document.getElementById("reliabilevel_WRP_NATSecondStep").checked){
			variablesSecondStep.push("reliabilevel");
		}
		if(document.getElementById("sourcecode_WRP_NATSecondStep").checked){
			variablesSecondStep.push("sourcecode");
		}
	}
	var xhr = new XMLHttpRequest();
	xhr.open("POST", "/variableChooserSecondStep", true);
	xhr.setRequestHeader("Content-Type", "application/json");
	xhr.send(JSON.stringify({ array: variablesSecondStep }));
	console.log("post vc:");
	console.log(variablesSecondStep);
	return variablesSecondStep;
}


async function AddColumns() {
	document.getElementById("addColumns").disabled = true;
	var yearRangeMin = "0";
	var yearRangeMax = "2022";
	var dataView;
	var grid;
	// let truefalse = checkCheckboxes();
	// if(truefalse == false){
	// 	document.getElementById("Warning").style.display = "block";
	// 	return;
	// }
	// else{
	// 	document.getElementById("Warning").style.display = "none";				
	// // }

	// variableChooser();
	// datasetChooserFirstStep();
	// variableChooserSecondStep();
	// datasetChooserSecondStep();

	var myData = await retrieveJSONSecondStep(); 
	//displayColumns.unshift("id");
	var col = [];
	keys = Object.keys(myData[0])
	for (var key in keys) {
		col.push({id: keys[key], name: keys[key], field: keys[key], toolTip: keys[key]});
	}
	var options = {
		enableCellNavigation: true,
        enableColumnReorder: false,
        explicitInitialization: true,
        editable: false,
	};
		
	$(function () {
		dataView = new Slick.Data.DataView();
		grid = new Slick.Grid("#myGrid", dataView, col, options);
		
        grid.setSelectionModel(new Slick.CellSelectionModel());

		dataView.onRowCountChanged.subscribe(function (e, args) {
		  grid.updateRowCount();
		  grid.render();
		});
		dataView.onRowsChanged.subscribe(function (e, args) {
		  grid.invalidateRows(args.rows);
		  grid.render();
		});
		
		$("#yearRangeMinimum").keyup(function (e) {
			Slick.GlobalEditorLock.cancelCurrentEdit();

			if (e.which == 27) {
			  this.value = "0";
			}

			yearRangeMin = this.value;
			filterYearMin = yearRangeMin;
			updateFilter();
		});
		$("#yearRangeMaximum").keyup(function (e) {
			Slick.GlobalEditorLock.cancelCurrentEdit();

			if (e.which == 27) {
			  this.value = "2022";
			}
			yearRangeMax = this.value;
			filterYearMax = yearRangeMax;
			updateFilter();
		});
		
		function updateFilter() {
			dataView.setFilterArgs({
			  yearRangeMin: yearRangeMin,
			  yearRangeMax: yearRangeMax
			});
			dataView.refresh();
		}
		grid.init();
		dataView.beginUpdate();
		dataView.setItems(myData);
		dataView.setFilterArgs({
			yearRangeMin: yearRangeMin,
			yearRangeMax: yearRangeMax
		});
		dataView.setFilter(filter);
		
		dataView.endUpdate();
		
		var filterPlugin = new Ext.Plugins.HeaderFilter({});

            filterPlugin.onFilterApplied.subscribe(function () {
                dataView.refresh();
                grid.resetActiveCell();
				filteredItems = dataView.getRows();
            });


            grid.registerPlugin(filterPlugin);

            

            grid.init();
            function filter(item, args) {
                var columns = grid.getColumns();
				var filterValues = [];
                var value = true;
				
                for (var i = 0; i < columns.length; i++) {
                    var col = columns[i];
                    filterValues = col.filterValues;
                    if (filterValues && filterValues.length > 0) {
                        value = value & _.contains(filterValues, item[col.field]);
                    }
                }
				
				if (args.yearRangeMin != "" && item["year"] < parseInt(args.yearRangeMin)) {
					value = false;
				}
				if (args.yearRangeMax != "" && item["year"] > parseInt(args.yearRangeMax)){
					value = false;
				}
				if(columns[1].filterValues != undefined){
					filterState1 = columns[1].filterValues;
				}
				if(dyadmonad == "dyadic"){
					if(columns[3].filterValues != undefined){
						filterState2 = columns[3].filterValues;
					}
				}
                return value;
            }
		filteredItems = dataView.getRows();
    });
	
	document.getElementById("optionsPanel").style.display = "inline-block";
	changeButtonSecondStep();	
}	

//Third STEP

async function filterGrid(){
	let filterItems = [filterYearMin, filterYearMax, filterState1, filterState2];
	var xhr = new XMLHttpRequest();
	xhr.open("POST", "/filterData", true);
	xhr.setRequestHeader("Content-Type", "application/json");
	xhr.send(JSON.stringify({ array: filterItems }));
	console.log("post filterGrid:")
	console.log(filterItems)
}

async function retrieveCSVThirdStep() {
	csv_file = [];
	await hideDownloadMessage();
	await filterGrid();
	try {
        const response = await fetch('downloadDf'); // issues a GET request by default
        const data = await response.json(); // data becomes the response from create_df(), which is { 'message': 'data processing successful', 'status': 200, 'new_df': new_df }
        // access the new_df data from the response
		const download_csv = data.csv; // this js constant is set to the new_df output from the response, which is a JSON array
        // populate myData with new_df
		csv_file = download_csv
    } catch (error) {
		console.error('error processing data:', error);
    } finally {
		showDownloadMessage();
	}
    return csv_file;
}

async function exportTableToCSV(filename) {
	await filterGrid();
	location.replace('downloadDf')
}

async function exportCitations(filename) {
	await filterGrid();
	location.replace('downloadCitations')
}


async function retrieveFirstStepVars() {
	try {
        const response = await fetch('firstStepVarJSON'); // issues a GET request by default
        const json_response = await response.json(); // data becomes the response from create_df(), which is { 'message': 'data processing successful', 'status': 200, 'new_df': new_df }
        // access the new_df data from the response
		const var_ids_r = json_response.var_id_json; // this js constant is set to the new_df output from the response, which is a JSON array
        // populate myData with new_df
		const var_names_r = json_response.name_json;
		const var_descrip_r = json_response.descrip_json;
		const var_dataset_r = json_response.dataset_json;

		var_names = JSON.parse(var_names_r);
		var_ids = JSON.parse(var_ids_r);
		var_descrips = JSON.parse(var_descrip_r);
		var_datasets= JSON.parse(var_dataset_r);

    } catch (error) {
		console.error('error processing data:', error);
    }
    return [var_names, var_descrips, var_ids, var_datasets];
}

async function first_step_vars() {
	var json_file = await retrieveFirstStepVars();
	var vars_name = [];
	var vars_id = [];
	var vars_descrip = [];
	var vars_dataset = [];
	var vars_type = [];
	var vars_pvu = [];
	for (let i = 0; i < json_file[2].length; i++){
		temp = json_file[2][i][0];
		for(let j = 0; j < temp.length; j++){
			vars_id.push(temp[j]);
		}
	}
	for (let i = 0; i < json_file[1].length; i++){
		temp_2 = json_file[1][i][0];
		for(let j = 0; j < temp_2.length; j++){
			vars_descrip.push(temp_2[j]);
		}
	}
	for (let i = 0; i < json_file[0][0].length; i++){
		temp_3 = json_file[0][0][i];
		for(let j = 0; j < temp_3.length; j++){
			vars_name.push(temp_3[j]);
		}
	}
	for (let i = 0; i < json_file[3].length; i++){
		temp_4 = json_file[3][i][0];
		for(let j = 0; j < temp_4.length; j++){
			vars_dataset.push(temp_4[j]);
		}
	}
	for (let i = 0; i < json_file[0][1].length; i++){
		temp_5 = json_file[0][1][i];
		for(let j = 0; j < temp_5.length; j++){
			vars_type.push(temp_5[j]);
		}
	}
	for (let i = 0; i < json_file[0][2].length; i++){
		temp_6 = json_file[0][2][i];
		for(let j = 0; j < temp_6.length; j++){
			vars_pvu.push(temp_6[j]);
		}
	}

	return [vars_name, vars_descrip, vars_id, vars_dataset, vars_type, vars_pvu];
}

async function retrieveSecondStepVars() {
	try {
        const response = await fetch('secondStepVarJSON'); // issues a GET request by default
        const json_response = await response.json(); // data becomes the response from create_df(), which is { 'message': 'data processing successful', 'status': 200, 'new_df': new_df }
        // access the new_df data from the response
		const var_ids_r = json_response.var_id_json; // this js constant is set to the new_df output from the response, which is a JSON array
        // populate myData with new_df
		const var_names_r = json_response.name_json;
		const var_descrip_r = json_response.descrip_json;
		const var_dataset_r = json_response.dataset_json;

		var_names = JSON.parse(var_names_r);
		var_ids = JSON.parse(var_ids_r);
		var_descrips = JSON.parse(var_descrip_r);
		var_datasets= JSON.parse(var_dataset_r);

    } catch (error) {
		console.error('error processing data:', error);
    }
    return [var_names, var_descrips, var_ids, var_datasets];
}

async function second_step_vars() {
	var json_file = await retrieveSecondStepVars();
	var vars_name = [];
	var vars_id = [];
	var vars_descrip = [];
	var vars_dataset = [];
	var vars_type = [];
	var vars_pvu = [];
	for (let i = 0; i < json_file[2].length; i++){
		temp = json_file[2][i][0];
		for(let j = 0; j < temp.length; j++){
			vars_id.push(temp[j]);
		}
	}
	for (let i = 0; i < json_file[1].length; i++){
		temp_2 = json_file[1][i][0];
		for(let j = 0; j < temp_2.length; j++){
			vars_descrip.push(temp_2[j]);
		}
	}
	for (let i = 0; i < json_file[0][0].length; i++){
		temp_3 = json_file[0][0][i];
		for(let j = 0; j < temp_3.length; j++){
			vars_name.push(temp_3[j]);
		}
	}
	for (let i = 0; i < json_file[3].length; i++){
		temp_4 = json_file[3][i][0];
		for(let j = 0; j < temp_4.length; j++){
			vars_dataset.push(temp_4[j]);
		}
	}
	for (let i = 0; i < json_file[0][1].length; i++){
		temp_5 = json_file[0][1][i];
		for(let j = 0; j < temp_5.length; j++){
			vars_type.push(temp_5[j]);
		}
	}
	for (let i = 0; i < json_file[0][2].length; i++){
		temp_6 = json_file[0][2][i];
		for(let j = 0; j < temp_6.length; j++){
			vars_pvu.push(temp_6[j]);
		}
	}

	return [vars_name, vars_descrip, vars_id, vars_dataset, vars_type, vars_pvu];
}

document.addEventListener("DOMContentLoaded", async function(event) {
	if (window.location.href.indexOf("dataUnlimVar.html") > -1) {
		document.getElementById("createButton").disabled = true;
		await VarTable_S1();
	}
});
//upload functions

function triggerValidation(el) {
	document.getElementById("uploadButton").disabled = true;
	var regex = new RegExp("(.*?)\.(csv)$");
	if (!(regex.test(el.value.toLowerCase()))) {
    	el.value = '';
    	alert('Please only input csv files.');
  	}
}

document.addEventListener("DOMContentLoaded", function(event) {
	if (window.location.href.indexOf("upload.html") > -1) {
		document.getElementById("uploadButton").disabled = true;
	}
});

function triggerValidationShared(el) {
	document.getElementById("uploadButtonShared").disabled = true;
	var regex = new RegExp("(.*?)\.(csv)$");
	if (!(regex.test(el.value.toLowerCase()))) {
    	el.value = '';
    	alert('Please only input csv files.');
  	}
}
document.addEventListener("DOMContentLoaded", function(event) {
	if (window.location.href.indexOf("shared.html") > -1) {
		document.getElementById("uploadButtonShared").disabled = true;
		
	}
});

string_2 = "";

document.addEventListener("DOMContentLoaded", function(event) {
	$(function() {
		$('#verifyFile').click(function() {
			document.getElementById("processing_upload").style.display = "inline-block";
			document.getElementById("verifyFile").disabled = true;
			var form_data = new FormData($('#uploadForm')[0]);
			
			$.ajax({
				type: 'POST',
				url: '/verifyFunction',
				data: form_data,
				contentType: false,
				cache: false,
				processData: false,
				success: function(data) {
					response = Object.entries(data);
					good = response[1][1];
					bad = response[0][1];
					string_1 = "These datasets are allowed to be uploaded: \n";
					string_2 = "";
					for (let g = 0; g < good.length-1; g++){
						string_2 += "    " + good[g] + '\n';
					}
					string_2 += "    " + good[good.length-1];
					if (good.length == 0){
						string_2 = "    none";
					}
					string_3 = "These datasets are not allowed to be uploaded because they did not have the necessary column names: \n";
					string_4 = "";
					for (let b = 0; b < bad.length-1; b++){
						string_4 += "    " + bad[b] + '\n';
					}
					string_4 += "    " + bad[bad.length-1];
					if (bad.length == 0){
						string_4 = "    none";
					}
					string_f = string_1 + string_2 + '\n' + string_3 + string_4;
					alert(string_f)
					if((bad.length == 0) && (good.length > 0) ){
						document.getElementById("uploadButton").disabled = false;
					}
					document.getElementById("verifyFile").disabled = false;
					document.getElementById("processing_upload").style.display = "none";
				},
			});
		});
	});
});

document.addEventListener("DOMContentLoaded", function(event) {
	$(function() {
		$('#uploadButton').click(function() {
			document.getElementById("processing_upload").style.display = "inline-block";
			document.getElementById("verifyFile").disabled = true;
			document.getElementById("uploadButton").disabled = true;
			var form_data = new FormData($('#uploadForm')[0]);
			for (var [key, value] of form_data.entries()) { 
				console.log(key, value);
			}
			$.ajax({
				type: 'POST',
				url: '/uploadFunction',
				data: form_data,
				contentType: false,
				cache: false,
				processData: false,
				success: function() {
					string_f = "Files successfully uploaded: \n" + string_2;
					alert(string_f);
					document.getElementById('file_input').value= null;
					document.getElementById("verifyFile").disabled = false;
					document.getElementById("processing_upload").style.display = "none";
				}
			})
		});
	});
});
string_2_shared = "";
document.addEventListener("DOMContentLoaded", function(event) {
	$(function() {
		$('#verifyFileShared').click(function() {
			document.getElementById("processing_uploadShared").style.display = "inline-block";
			document.getElementById("verifyFileShared").disabled = true;
			var form_data = new FormData($('#file-upload-form')[0]);
			for (var [key, value] of form_data.entries()) { 
				console.log(key, value);
			}
			$.ajax({
				type: 'POST',
				url: '/verifyFunctionShared',
				data: form_data,
				contentType: false,
				cache: false,
				processData: false,
				success: function(data) {
					response = Object.entries(data);
					good = response[1][1];
					bad = response[0][1];
					string_1 = "These datasets are allowed to be uploaded: \n";
					string_2_shared = "";
					for (let g = 0; g < good.length-1; g++){
						string_2_shared += "    " + good[g] + '\n';
					}
					string_2_shared += "    " + good[good.length-1];
					if (good.length == 0){
						string_2_shared = "    none";
					}
					string_3 = "These datasets are not allowed to be uploaded because they did not have the necessary column names: \n";
					string_4 = "";
					for (let b = 0; b < bad.length-1; b++){
						string_4 += "    " + bad[b] + '\n';
					}
					string_4 += "    " + bad[bad.length-1];
					if (bad.length == 0){
						string_4 = "    none";
					}
					string_f = string_1 + string_2_shared + '\n' + string_3 + string_4;
					alert(string_f)
					if((bad.length == 0) && (good.length > 0) ){
						document.getElementById("uploadButtonShared").disabled = false;
					}
					document.getElementById("verifyFileShared").disabled = false;
					document.getElementById("processing_uploadShared").style.display = "none";
				},
			});
		});
	});
});

document.addEventListener("DOMContentLoaded", function(event) {
	$(function() {
		$('#uploadButtonShared').click(function() {
			document.getElementById("processing_uploadShared").style.display = "inline-block";
			document.getElementById("verifyFileShared").disabled = true;
			document.getElementById("uploadButtonShared").disabled = true;
			var form_data = new FormData($('#file-upload-form')[0]);
			for (var [key, value] of form_data.entries()) { 
				console.log(key, value);
			}
			$.ajax({
				type: 'POST',
				url: '/shared.html',
				data: form_data,
				contentType: false,
				cache: false,
				processData: false,
				success: function() {
					string_f = "Files successfully uploaded: \n" + string_2_shared;
					alert(string_f);
					document.getElementById('file_input_shared').value= null;
					document.getElementById('file_input_shared').value= "";
					document.getElementById('drop-area').value= "";

					document.getElementById('file-list').innerHTML = "";
					document.getElementById("verifyFileShared").disabled = false;
					document.getElementById("processing_uploadShared").style.display = "none";
				}
			})
		});
	});
});