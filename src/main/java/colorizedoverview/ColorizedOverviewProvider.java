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

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;

import javax.swing.JComponent;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.GoToService;
import ghidra.app.util.viewer.listingpanel.OverviewProvider;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.util.task.SwingUpdateManager;

class ColorizedOverviewProvider extends JComponent implements OverviewProvider {
	private static final Color DefaultColor = Color.BLACK;
	private final PluginTool tool;
	private final ColorizingService colorizingService;
	private final SwingUpdateManager refreshUpdater = new SwingUpdateManager(100, 15000, () -> computeColors());
	private AddressIndexMap map;
	// maps y-position to color.
	// a NULL-entry indicate that the color for that line needs to be computed. 
	private Color[] colors;
	private Color[] colors2;
	
	public ColorizedOverviewProvider(PluginTool tool, ColorizingService colorizingService) {
		this.tool = tool;
		this.colorizingService = colorizingService;
		addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				if (e.getButton()==MouseEvent.BUTTON1) {
					Address address = y2address(e.getY());
					GoToService gotoService = tool.getService(GoToService.class);
					if (gotoService!=null) {
						gotoService.goTo(address);
					}
				}
			}
		});
	}
	
	@Override
	public Dimension getPreferredSize() {
		return new Dimension(16, 1);
	}

	@Override
	public JComponent getComponent() {
		return this;
	}

	@Override
	public void setAddressIndexMap(AddressIndexMap map) {
		this.map = map;
		resetColors();
	}
	
	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		
		// fill the background
		g.setColor(getBackground());
		final var width = getWidth();
		final var height = getHeight();
		g.fillRect(0, 0, width-1, height-1);
		
		// draw the color lines
		if(colors!=null) {
			final var colorBarWidth = width - 3;
			final var colorBarWidth2 = (width - 3)/2;
			for (int y = 0; y<height; y++) {
				final var color = getColor(y);
				final var color2 = getColor2(y);
				
				g.setColor(color);
				if(color2==null) {
					g.fillRect(1, y, colorBarWidth, 1);
				}
				else {
					g.fillRect(1, y, colorBarWidth2, 1);
					g.setColor(color2);
					g.fillRect(1+colorBarWidth2, y, colorBarWidth-colorBarWidth2, 1);
				}			
			}
		}
		
		// do we need to (re)compute the colors?
		if(colors==null || colors.length!=height) {	
			resetColors();
		}
	}
	
	/**
	 * Triggers a (re)computation of the colors corresponding to the
	 * respective y position inside this component. The actual computation is
	 * done later by the Swing updater in order to prevent that we block
	 * Swing's paint thread.
	 */
	private void resetColors() {
		colors = new Color[getHeight()];
		colors2 = new Color[getHeight()];
		refreshUpdater.updateLater();	
	}
	
	/**
	 * Returns the color for the y position in the overview.
	 * Just returns a default color if we have not already computed the
	 * color for that position.
	 */
	private Color getColor(int y) {			
		return colors!=null && y<colors.length && colors[y]!=null ? colors[y] : DefaultColor;
	}
	
	private Color getColor2(int y) {			
		return colors2!=null && y<colors2.length ? colors2[y] : null;
	}
	
	/**
	 * Computes the colors to be used at each possible y position in the
	 * color bar. Only the lines that need a refresh are computed.
	 */
	private void computeColors() {			
		if(map==null || map.getIndexCount().equals(BigInteger.ZERO)) {
			Arrays.fill(colors, getBackground());
		}
		else {
			final var bigTotal = BigInteger.valueOf(colors.length);			
			for(int y=0;y<colors.length;y++) {
				if (colors[y] == null) {
					// Determine the range in the address map [startIndex,endIndex[ that this
					// pixel line represents. 
					final var startIndex = map.getIndexCount().multiply(BigInteger.valueOf(y)).divide(bigTotal);
					final var endIndex = map.getIndexCount().multiply(BigInteger.valueOf(y+1)).divide(bigTotal);
					
					// Find the first color used in the block
					Color color = null;
					BigInteger i=startIndex;
					for(;i.compareTo(endIndex)<0;i=i.add(BigInteger.ONE)) {
						color = colorizingService.getBackgroundColor(map.getAddress(i));
						if(color!=null) {
							break;
						}
					}
					colors[y] = color==null ? DefaultColor : color;
					
					// Find the second color used in the block
					Color color2 = null;
					for(i=i.add(BigInteger.ONE);i.compareTo(endIndex)<0;i=i.add(BigInteger.ONE)) {
						color2 = colorizingService.getBackgroundColor(map.getAddress(i));
						if(color2!=null && !color2.equals(color)) break;
					}
					colors2[y] = color2; // no default color
				}
			}
		}
		repaint();
	}
	
	/**
	 * Translates a program address to an y-position.
	 * Returns -1 if the address is outside the program's address map.
	 */
	private int adress2y(Address address) {
		final var addressIndex = map.getIndex(address);
		if(addressIndex==null) {
			return -1;
		}
		final var bigHeight = BigInteger.valueOf(getHeight());
		final var indexCount = map.getIndexCount();
		return addressIndex.multiply(bigHeight).divide(indexCount).intValue();
	}
	
	/**
	 * Translates an y-position inside the component to an address.
	 */
	private Address y2address(int y) {
		final var bigHeight = BigInteger.valueOf(getHeight());
		final var bigY = BigInteger.valueOf(y);
		final var bigIndex = map.getIndexCount().multiply(bigY).divide(bigHeight);
		return map.getAddress(bigIndex);
	}
	
	/**
	 * Tells the component to recompute and repaint the color lines
	 * for the indicated address range. 
	 */
	public void refresh(Address start, Address end) {
		if(start==null) {
			return;
		}
		if(end==null) {
			end = start;
		}
		final var startY = adress2y(start);
		final var endY = adress2y(end);
		for (int y = startY; y<=endY; y++) {
			if (y>=0 & y<colors.length) {
				colors[y] = null;
			}
		}
		refreshUpdater.updateLater();
	}
}