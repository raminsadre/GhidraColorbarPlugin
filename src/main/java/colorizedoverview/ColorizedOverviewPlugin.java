/*
 * @author Ramin Sadre
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package colorizedoverview;

import docking.ActionContext;
import docking.ActionToGuiHelper;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramChangeRecord;
import resources.ResourceManager;

@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Colorized Overview Plugin",
	description = "Shows an overview of colorized lines",
	servicesRequired = { CodeViewerService.class, ColorizingService.class }
)

/**
 * This plugin has been derived from the OverviewColorPlugin shipped
 * with Ghidra.
 * It would have been much more elegant to implement this plugin as an
 * OverviewColorService because it would then nicely integrate into the list of
 * existing overview color services (like AddressType and EntropyOverview).
 * Unfortunately, the OverviewColorComponent does not publish all the methods
 * and fields that are needed by this plugin :(
 */

public class ColorizedOverviewPlugin extends ProgramPlugin implements DomainObjectListener {
	private CodeViewerService codeViewerService;
	private ToggleDockingAction action;
	private ColorizedOverviewProvider provider;
	private ColorizingService colorizingService;
	
	public ColorizedOverviewPlugin(PluginTool tool) {
		super(tool, false, false);
	}

	@Override
	public void init() {
		super.init();
		colorizingService = tool.getService(ColorizingService.class);
		codeViewerService = tool.getService(CodeViewerService.class);		
		action = new ToggleDockingAction("Colorization overview", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if(isSelected()) {
					provider = new ColorizedOverviewProvider(tool, colorizingService);
					codeViewerService.addOverviewProvider(provider);
				}
				else {
					codeViewerService.removeOverviewProvider(provider);
					provider = null;
				}
				
				// Why this strange method call here?
				// Calling this method is just a crutch to call the package-
				// level "scheduleUpdate()" method of the window manager.
				// Without it, the listing view will not be repainted after the
				// provider component has been added or removed and will
				// just stay blank.
				// Note that the OverviewColorPlugin shipped with Ghidra doesn't
				// need to do this because it calls addAction/removeAction which
				// indirectly also calls scheduleUpdate().
				new ActionToGuiHelper(tool.getWindowManager()).keyBindingsChanged();
			}
		};
		action.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/toolbar.png")));
		action.setDescription("Shows an overview of the colorized line");
		codeViewerService.addLocalAction(action);
	}

	@Override
	protected void cleanup() {
		codeViewerService.removeLocalAction(action);
	}
	
	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
	}
	
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if(provider!=null) {
			for(int i = 0; i < ev.numRecords(); i++) {
				DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);
				if(doRecord instanceof ProgramChangeRecord) {
					ProgramChangeRecord record = (ProgramChangeRecord)doRecord;
					provider.refresh(record.getStart(), record.getEnd());
				}
			}
		}
	}
}
